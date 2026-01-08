# DCG Improvement Plan

> **Author:** Claude Opus 4.5
> **Date:** 2026-01-07
> **Status:** Proposal
> **Scope:** Strategic improvements to make DCG more robust, reliable, performant, intuitive, and user-friendly

---

## Executive Summary

This document presents five strategic improvements to the Destructive Command Guard (DCG) project, selected from an initial pool of 30 ideas through rigorous evaluation. Each improvement was assessed on four dimensions:

1. **Impact** — How significantly does this improve the user experience?
2. **Pragmatism** — How practical is implementation given current architecture?
3. **User Perception** — How will users receive this change?
4. **Risk** — What could go wrong, and how do we mitigate it?

The five selected improvements form a coherent strategy that transforms DCG from "a hook that blocks things" into "a trusted security layer that users understand, can customize, and that protects entire teams."

### The Five Improvements (Ranked)

| Rank | Improvement | Primary Value |
|------|-------------|---------------|
| 1 | Explain Mode with Full Decision Trace | Transparency & Trust |
| 2 | Project-Specific Allowlists with Learning | False Positive Resolution |
| 3 | Pre-Commit Hook Integration | Codebase Protection |
| 4 | Comprehensive Test Infrastructure | Reliability Guarantee |
| 5 | GitHub Action for CI/CD Protection | Team-Wide Security |

---

## Table of Contents

1. [Explain Mode with Full Decision Trace](#1-explain-mode-with-full-decision-trace)
2. [Project-Specific Allowlists with Learning](#2-project-specific-allowlists-with-learning)
3. [Pre-Commit Hook Integration](#3-pre-commit-hook-integration)
4. [Comprehensive Test Infrastructure](#4-comprehensive-test-infrastructure)
5. [GitHub Action for CI/CD Protection](#5-github-action-for-cicd-protection)
6. [Implementation Roadmap](#implementation-roadmap)
7. [Success Metrics](#success-metrics)
8. [Appendix: Ideas Not Selected](#appendix-ideas-not-selected)

---

## 1. Explain Mode with Full Decision Trace

### Overview

Explain mode is a new `dcg explain "command"` subcommand that reveals the complete decision-making process for any command. It shows users exactly why a command was blocked or allowed, what patterns were checked, and what alternatives exist.

### The Problem It Solves

When DCG blocks a command, users are presented with a reason, but not the full context:

```
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  BLOCKED: Destructive Command Detected                   ║
╠══════════════════════════════════════════════════════════════╣
║  Command: git reset --hard HEAD~5                            ║
║  Reason:  Hard reset can permanently lose commits            ║
║  Pack:    core.git                                           ║
╚══════════════════════════════════════════════════════════════╝
```

Users immediately ask:
- "Why was this specific pattern matched and not another?"
- "What regex actually matched my command?"
- "Are there safe patterns I could have used instead?"
- "How do I test if my allowlist entry will work?"

Without answers, users lose trust. They may disable DCG entirely rather than debug it.

### The Solution

Explain mode provides complete transparency:

```
$ dcg explain "git reset --hard HEAD~5"

╔══════════════════════════════════════════════════════════════════════╗
║                     DCG Decision Analysis                            ║
║                                                                      ║
║  Input:    git reset --hard HEAD~5                                   ║
║  Decision: DENY                                                      ║
║  Latency:  0.847ms                                                   ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  PIPELINE TRACE                                                      ║
║  ─────────────────────────────────────────────────────────────────── ║
║                                                                      ║
║  [1] Input Parsing                                          0.012ms  ║
║      ├─ Tool: Bash                                                   ║
║      └─ Command extracted: "git reset --hard HEAD~5"                 ║
║                                                                      ║
║  [2] Quick Reject Filter                                    0.003ms  ║
║      ├─ Checking for: git, rm, docker, kubectl, ...                  ║
║      ├─ Found: "git" at position 0                                   ║
║      └─ Result: PASSED (command requires full analysis)              ║
║                                                                      ║
║  [3] Path Normalization                                     0.001ms  ║
║      ├─ Input:  git reset --hard HEAD~5                              ║
║      ├─ Output: git reset --hard HEAD~5                              ║
║      └─ Note: No path prefix to strip                                ║
║                                                                      ║
║  [4] Project Allowlist Check                                0.015ms  ║
║      ├─ Loaded: .dcg/allowlist.toml (3 entries)                      ║
║      ├─ Checked patterns:                                            ║
║      │   └─ "git commit -m" — NO MATCH                               ║
║      │   └─ "bd create" — NO MATCH                                   ║
║      │   └─ "echo" — NO MATCH                                        ║
║      └─ Result: No allowlist match                                   ║
║                                                                      ║
║  [5] Safe Pattern Evaluation                                0.234ms  ║
║      ├─ Pack: core.git (34 safe patterns)                            ║
║      ├─ Checked patterns:                                            ║
║      │   └─ checkout-new-branch: NO MATCH                            ║
║      │   └─ checkout-orphan: NO MATCH                                ║
║      │   └─ restore-staged-long: NO MATCH                            ║
║      │   └─ ... (31 more patterns checked)                           ║
║      └─ Result: No safe pattern matched                              ║
║                                                                      ║
║  [6] Destructive Pattern Evaluation                         0.156ms  ║
║      ├─ Pack: core.git                                               ║
║      │   ├─ Pattern: hard-reset                                      ║
║      │   │   ├─ Regex: git\s+reset\s+--hard                          ║
║      │   │   ├─ Match: "git reset --hard" (positions 0-15)           ║
║      │   │   └─ Reason: Hard reset can permanently lose commits      ║
║      │   └─ MATCHED — stopping evaluation                            ║
║      └─ Result: DENY (core.git:hard-reset)                           ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  MATCH VISUALIZATION                                                 ║
║  ─────────────────────────────────────────────────────────────────── ║
║                                                                      ║
║      git reset --hard HEAD~5                                         ║
║      ▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔                                            ║
║      └─── matched ────┘                                              ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  💡 SUGGESTIONS                                                      ║
║  ─────────────────────────────────────────────────────────────────── ║
║                                                                      ║
║  Safe alternatives:                                                  ║
║  • git reset --soft HEAD~5     — Keeps changes staged                ║
║  • git reset --mixed HEAD~5    — Keeps changes unstaged (default)    ║
║  • git revert HEAD~5..HEAD     — Creates inverse commits (safe)      ║
║  • git stash                   — Saves changes before reset          ║
║                                                                      ║
║  To allow this specific command:                                     ║
║  • dcg allow "git reset --hard HEAD~5" --reason "Intentional reset"  ║
║                                                                      ║
║  To allow all hard resets (use with caution):                        ║
║  • dcg allow --pattern "git reset --hard" --reason "..."             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

### User Stories

**Story 1: Debugging a False Positive**
> As a developer, I want to understand why `bd create --description="Fix rm -rf bug"` was blocked, so I can add an appropriate allowlist entry.

With explain mode:
```bash
$ dcg explain 'bd create --description="Fix rm -rf bug"'
# Shows that "rm -rf" in the description triggered core.filesystem:rm-rf
# Suggests: dcg allow --pattern "bd create --description" --context string-argument
```

**Story 2: Pattern Development**
> As a pack author, I want to test my new pattern without executing commands, so I can verify it matches what I expect.

With explain mode:
```bash
$ dcg explain "docker system prune --all --force"
# Shows whether containers.docker pack is reached
# Shows which pattern matched (or didn't)
# Shows timing to verify performance is acceptable
```

**Story 3: Learning the System**
> As a new user, I want to understand what DCG protects against, so I can trust it and configure it appropriately.

With explain mode:
```bash
$ dcg explain "git push --force origin main"
# Educational output showing the strict_git pack
# Explains why force-push to main is dangerous
# Shows alternatives like --force-with-lease
```

### Technical Design

#### New Module: `src/explain.rs`

```rust
/// Trace of a single decision step in the pipeline.
#[derive(Debug, Clone)]
pub struct TraceStep {
    pub name: &'static str,
    pub duration: Duration,
    pub details: TraceDetails,
}

#[derive(Debug, Clone)]
pub enum TraceDetails {
    InputParsing {
        tool_name: String,
        command: String,
    },
    QuickReject {
        keywords_checked: Vec<&'static str>,
        keyword_found: Option<(&'static str, usize)>,
        result: QuickRejectResult,
    },
    Normalization {
        input: String,
        output: String,
        transformations: Vec<String>,
    },
    AllowlistCheck {
        entries_checked: usize,
        matched_entry: Option<AllowlistEntry>,
    },
    SafePatternEval {
        pack: String,
        patterns_checked: Vec<PatternResult>,
        matched: Option<String>,
    },
    DestructivePatternEval {
        pack: String,
        pattern_name: String,
        regex: String,
        matched_span: Option<(usize, usize)>,
        reason: String,
    },
}

/// Complete trace of a command analysis.
#[derive(Debug)]
pub struct ExplainTrace {
    pub command: String,
    pub decision: Decision,
    pub steps: Vec<TraceStep>,
    pub total_duration: Duration,
    pub suggestions: Vec<Suggestion>,
}

/// Suggestion for the user.
#[derive(Debug, Clone)]
pub struct Suggestion {
    pub category: SuggestionCategory,
    pub text: String,
    pub command: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SuggestionCategory {
    SafeAlternative,
    AllowlistEntry,
    Documentation,
}
```

#### Integration with Decision Pipeline

The key insight is that the decision pipeline already has all this information—we just discard it. The change is to optionally collect it:

```rust
/// Check a command, optionally collecting an explain trace.
pub fn check_command_with_trace(
    command: &str,
    config: &Config,
    trace: Option<&mut ExplainTrace>,
) -> Decision {
    let start = Instant::now();

    // Step 1: Quick reject
    let qr_start = Instant::now();
    let qr_result = global_quick_reject(command, config);
    if let Some(t) = trace.as_mut() {
        t.steps.push(TraceStep {
            name: "Quick Reject Filter",
            duration: qr_start.elapsed(),
            details: TraceDetails::QuickReject { /* ... */ },
        });
    }

    if qr_result == QuickRejectResult::Skip {
        return Decision::Allow;
    }

    // ... continue pipeline, recording each step
}
```

In hook mode, we pass `None` for the trace, so there's zero overhead:

```rust
// Hook mode (production): no trace overhead
let decision = check_command_with_trace(&command, &config, None);

// Explain mode: collect full trace
let mut trace = ExplainTrace::new(&command);
let decision = check_command_with_trace(&command, &config, Some(&mut trace));
println!("{}", trace.format(OutputFormat::Pretty));
```

#### CLI Integration

```rust
#[derive(Parser)]
enum Command {
    /// Explain why a command would be blocked or allowed
    Explain {
        /// The command to analyze
        command: String,

        /// Output format
        #[arg(long, default_value = "pretty")]
        format: OutputFormat,

        /// Show timing information
        #[arg(long)]
        timing: bool,

        /// Show all patterns checked, not just the match
        #[arg(long)]
        verbose: bool,
    },
    // ... other commands
}

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Pretty,  // Colorful box drawing (default)
    Json,    // Machine-readable JSON
    Compact, // Single-line summary
}
```

### Output Formats

#### Pretty (Default)

The box-drawing format shown above, with colors:
- Green for allowed/passed steps
- Red for blocked/matched patterns
- Yellow for warnings
- Blue for suggestions
- Dim gray for timing information

#### JSON (Machine-Readable)

```json
{
  "command": "git reset --hard HEAD~5",
  "decision": "deny",
  "total_duration_us": 847,
  "steps": [
    {
      "name": "Quick Reject Filter",
      "duration_us": 3,
      "result": "passed",
      "keyword_found": "git",
      "position": 0
    },
    {
      "name": "Destructive Pattern Evaluation",
      "duration_us": 156,
      "result": "matched",
      "pack": "core.git",
      "pattern": "hard-reset",
      "regex": "git\\s+reset\\s+--hard",
      "matched_text": "git reset --hard",
      "matched_span": [0, 15],
      "reason": "Hard reset can permanently lose commits"
    }
  ],
  "suggestions": [
    {
      "category": "safe_alternative",
      "text": "git reset --soft HEAD~5",
      "description": "Keeps changes staged"
    }
  ]
}
```

#### Compact (One-Line)

```
DENY core.git:hard-reset "git reset --hard" — Hard reset can permanently lose commits (0.847ms)
```

### Suggestions Database

Each destructive pattern should have associated suggestions:

```rust
static SUGGESTIONS: LazyLock<HashMap<&str, Vec<Suggestion>>> = LazyLock::new(|| {
    hashmap! {
        "core.git:hard-reset" => vec![
            Suggestion::safe_alt("git reset --soft HEAD~N", "Keeps changes staged"),
            Suggestion::safe_alt("git reset --mixed HEAD~N", "Keeps changes unstaged"),
            Suggestion::safe_alt("git stash", "Saves changes before reset"),
            Suggestion::safe_alt("git revert HEAD~N..HEAD", "Creates inverse commits"),
        ],
        "core.git:force-push" => vec![
            Suggestion::safe_alt("git push --force-with-lease", "Fails if remote has new commits"),
            Suggestion::doc("https://docs.dcg.dev/patterns/force-push"),
        ],
        "core.filesystem:rm-rf" => vec![
            Suggestion::safe_alt("rm -ri", "Interactive mode, confirms each file"),
            Suggestion::safe_alt("trash-put", "Moves to trash instead of deleting"),
            Suggestion::safe_alt("mv /path /tmp/backup-$(date +%s)", "Backup first"),
        ],
        // ... more patterns
    }
});
```

### Edge Cases

1. **Very long commands**: Truncate display but show full command in JSON output
2. **Binary/unprintable content**: Escape or replace with placeholders
3. **Multiple matches**: Show all matches in order, highlight first (decisive) match
4. **No match (allowed)**: Show that all patterns were checked with no match
5. **Allowlist match**: Show which allowlist entry matched and why

### Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| User understanding | 90% can explain why a command was blocked | Survey |
| Debug time | <2 minutes to understand any block | User testing |
| False positive resolution | 80% resolved with explain + allow | Telemetry |
| Adoption | 50% of users use explain at least once | CLI analytics |

### Implementation Phases

**Phase 1: Core Trace Infrastructure (2-3 days)**
- Add `ExplainTrace` struct and builder
- Modify decision pipeline to optionally collect trace
- Basic pretty-print output

**Phase 2: Rich Output (1-2 days)**
- JSON and compact formats
- Match visualization with highlighting
- Timing breakdown

**Phase 3: Suggestions (2-3 days)**
- Build suggestions database for all patterns
- Context-aware suggestion selection
- Documentation links

**Phase 4: Polish (1-2 days)**
- Error handling for malformed commands
- Performance optimization (ensure zero overhead in hook mode)
- Documentation and examples

---

## 2. Project-Specific Allowlists with Learning

### Overview

Project-specific allowlists allow users to define rules that override DCG's default behavior for their specific project. Combined with an interactive learning mode, the system can automatically build allowlists from user feedback on false positives.

### The Problem It Solves

DCG's pattern-based approach inevitably produces false positives. Some examples:

1. **Documentation commands**: `bd create --description="This blocks rm -rf attacks"`
2. **Commit messages**: `git commit -m "Fix the git reset --hard detection"`
3. **Search patterns**: `rg "rm -rf" src/` (searching for the pattern, not executing it)
4. **Echo/print statements**: `echo "Example: docker system prune --all"`
5. **Test fixtures**: Commands in test files that define what to block

Currently, users have no recourse except to:
- Disable DCG entirely (dangerous)
- Modify the source code (impractical)
- Wait for upstream fixes (slow)

### The Solution

A `.dcg/allowlist.toml` file that lives in the project repository:

```toml
# .dcg/allowlist.toml
# Project-specific allowlist for DCG
# This file is committed to the repository and shared with the team.

# Beads CLI uses descriptions that may contain dangerous patterns as examples
[[allow]]
command_prefix = "bd create"
context = "string-argument"
reason = "Beads CLI descriptions are documentation, not executable code"
added_by = "alice@example.com"
added_at = 2026-01-07T15:30:00Z

# Git commit messages may reference dangerous commands being fixed
[[allow]]
command_prefix = "git commit -m"
context = "string-argument"
reason = "Commit messages are documentation"
added_by = "interactive"
added_at = 2026-01-07T16:45:00Z

# Ripgrep searching for patterns is safe
[[allow]]
command_prefix = "rg"
context = "search-pattern"
reason = "Searching for patterns is not executing them"

# Specific command that was a false positive
[[allow]]
exact_command = "rm -rf /tmp/dcg-test-*"
reason = "Test cleanup in CI, validated path"
expires_at = 2026-06-01T00:00:00Z  # Optional expiration

# Pattern-based allowlist (use with caution)
[[allow]]
pattern = "echo \"Example:.*\""
reason = "Echo statements with 'Example:' prefix are documentation"
added_by = "bob@example.com"
risk_acknowledged = true  # Required for pattern-based allows
```

### Interactive Learning Mode

When DCG blocks a command in interactive mode, it can prompt the user:

```
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  BLOCKED: Potentially Destructive Command                ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Command: bd create --description="Blocks rm -rf attacks"    ║
║  Pattern: core.filesystem:rm-rf                              ║
║  Matched: "rm -rf" in argument string                        ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  This appears to be a string argument, not executable code.  ║
║                                                              ║
║  Options:                                                    ║
║  [1] Block this command (default)                            ║
║  [2] Allow this once and continue                            ║
║  [3] Add to project allowlist (remembers for future)         ║
║  [4] Explain why this was blocked                            ║
║                                                              ║
║  Choice [1/2/3/4]:                                           ║
╚══════════════════════════════════════════════════════════════╝
```

If the user selects `[3]`, DCG:
1. Prompts for a reason (or uses auto-detected context)
2. Appends to `.dcg/allowlist.toml`
3. Allows the command to proceed
4. Never blocks this pattern again for this project

### Allowlist Entry Types

#### 1. Exact Command Match

```toml
[[allow]]
exact_command = "rm -rf /tmp/test-artifacts"
reason = "CI cleanup of test artifacts"
```

- Most restrictive (safest)
- Only matches the exact command string
- Good for specific commands that are known-safe

#### 2. Command Prefix Match

```toml
[[allow]]
command_prefix = "bd create"
context = "string-argument"
reason = "Beads CLI descriptions are documentation"
```

- Matches any command starting with the prefix
- Combined with `context` for additional safety
- Good for tools with known-safe argument patterns

#### 3. Pattern Match

```toml
[[allow]]
pattern = "echo \"Example:.*\""
reason = "Documentation examples"
risk_acknowledged = true  # REQUIRED
```

- Most flexible (least safe)
- Requires explicit `risk_acknowledged = true`
- Good for complex patterns but requires careful review

### Context Types

The `context` field provides semantic understanding of why a match is safe:

| Context | Meaning | Example |
|---------|---------|---------|
| `string-argument` | Match is inside a quoted string argument | `git commit -m "fix rm -rf"` |
| `search-pattern` | Match is a search/grep pattern | `rg "rm -rf" src/` |
| `heredoc-example` | Match is in a heredoc used as documentation | `cat << 'EOF'` |
| `comment` | Match is in a comment | `# Don't use rm -rf` |
| `disabled-code` | Match is in disabled/commented code | `# rm -rf /tmp` |

### CLI Commands

```bash
# Add an allowlist entry manually
$ dcg allow "bd create --description" --context string-argument --reason "Beads descriptions"
Added to .dcg/allowlist.toml

# Add with expiration (temporary allow)
$ dcg allow --once "rm -rf /tmp/old-build"
Allowed once. Not added to allowlist.

$ dcg allow "rm -rf /tmp/ci-*" --expires 2026-02-01 --reason "CI cleanup, expires Feb 1"
Added to .dcg/allowlist.toml with expiration

# List current allowlist
$ dcg allowlist
┌─────────────────────────────────────────────────────────────────┐
│ Project Allowlist: .dcg/allowlist.toml                          │
├──────────────────────┬──────────────────┬───────────────────────┤
│ Pattern              │ Context          │ Reason                │
├──────────────────────┼──────────────────┼───────────────────────┤
│ bd create            │ string-argument  │ Beads descriptions    │
│ git commit -m        │ string-argument  │ Commit messages       │
│ rg                   │ search-pattern   │ Search is safe        │
└──────────────────────┴──────────────────┴───────────────────────┘

# Remove an allowlist entry
$ dcg allowlist remove "bd create"
Removed from .dcg/allowlist.toml

# Validate allowlist (check for risky entries)
$ dcg allowlist validate
⚠️  Warning: Pattern "rm -rf.*" is very broad. Consider using exact_command.
✓  3 entries validated
```

### Security Considerations

#### 1. Allowlist Audit Trail

Every allowlist entry includes:
- `added_by`: Who added it (email, username, or "interactive")
- `added_at`: When it was added (ISO 8601 timestamp)
- `reason`: Why it's allowed

This creates an audit trail that can be reviewed in code review.

#### 2. Risk Acknowledgment

Pattern-based allowlists require explicit acknowledgment:

```toml
[[allow]]
pattern = "rm -rf /tmp/.*"
reason = "Cleanup temp files"
risk_acknowledged = true  # Without this, dcg will warn/reject
```

#### 3. Expiration

Temporary allowlists can have expiration dates:

```toml
[[allow]]
exact_command = "docker system prune -af"
reason = "One-time cleanup for migration"
expires_at = 2026-01-15T00:00:00Z
```

After expiration, the entry is ignored (and can be cleaned up).

#### 4. Validation on Load

DCG validates the allowlist on load:
- Warns about overly broad patterns
- Errors on invalid regex in patterns
- Warns about expired entries
- Checks for conflicting entries

### Team Workflow

1. **Developer hits false positive** → Uses interactive mode or `dcg allow`
2. **Entry added to `.dcg/allowlist.toml`** → Committed with code
3. **Code review** → Team reviews allowlist changes like any code
4. **Merged** → Entire team benefits from the allowlist entry

This creates a collaborative, auditable process for managing false positives.

### Technical Design

#### Allowlist Module: `src/allowlist.rs`

```rust
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
pub struct Allowlist {
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AllowEntry {
    Exact(ExactAllow),
    Prefix(PrefixAllow),
    Pattern(PatternAllow),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExactAllow {
    pub exact_command: String,
    pub reason: String,
    #[serde(default)]
    pub added_by: Option<String>,
    #[serde(default)]
    pub added_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrefixAllow {
    pub command_prefix: String,
    #[serde(default)]
    pub context: Option<AllowContext>,
    pub reason: String,
    // ... metadata fields
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PatternAllow {
    pub pattern: String,
    pub reason: String,
    pub risk_acknowledged: bool,  // Required to be true
    // ... metadata fields
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AllowContext {
    StringArgument,
    SearchPattern,
    HeredocExample,
    Comment,
    DisabledCode,
}

impl Allowlist {
    /// Load allowlist from project directory.
    pub fn load(project_root: &Path) -> Result<Self, AllowlistError> {
        let path = project_root.join(".dcg/allowlist.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)?;
        let allowlist: Self = toml::from_str(&content)?;
        allowlist.validate()?;
        Ok(allowlist)
    }

    /// Check if a command matches any allowlist entry.
    pub fn matches(&self, command: &str) -> Option<&AllowEntry> {
        for entry in &self.allow {
            if entry.is_expired() {
                continue;
            }
            if entry.matches(command) {
                return Some(entry);
            }
        }
        None
    }

    /// Add a new entry and save to disk.
    pub fn add_and_save(&mut self, entry: AllowEntry, path: &Path) -> Result<(), AllowlistError> {
        self.allow.push(entry);
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
```

#### Integration with Decision Pipeline

```rust
pub fn check_command(command: &str, config: &Config) -> Decision {
    // ... quick reject ...

    // Check allowlist EARLY (before expensive pattern matching)
    if let Some(allowlist) = &config.allowlist {
        if let Some(entry) = allowlist.matches(command) {
            return Decision::Allow {
                reason: format!("Allowlist: {}", entry.reason()),
            };
        }
    }

    // ... continue with pattern matching ...
}
```

### Implementation Phases

**Phase 1: Core Allowlist (2-3 days)**
- Allowlist data structures and parsing
- Load `.dcg/allowlist.toml` on startup
- Exact and prefix matching
- Integration with decision pipeline

**Phase 2: CLI Commands (1-2 days)**
- `dcg allow` command
- `dcg allowlist` (list, remove, validate)
- Proper TOML formatting on save

**Phase 3: Interactive Learning (2-3 days)**
- TTY detection
- Interactive prompt on block
- Automatic entry creation
- Context detection heuristics

**Phase 4: Pattern Matching & Safety (1-2 days)**
- Pattern-based allows with risk acknowledgment
- Expiration handling
- Validation and warnings
- Documentation

---

## 3. Pre-Commit Hook Integration

### Overview

Pre-commit hook integration allows DCG to scan files before they're committed, catching dangerous patterns in shell scripts, CI configs, Dockerfiles, and other files that will be executed later.

### The Problem It Solves

The current DCG hook only protects real-time command execution by Claude. But dangerous commands can enter the codebase through:

1. **Shell scripts**: A developer writes `rm -rf $UNINIT_VAR` in a cleanup script
2. **CI configs**: A GitHub Action uses `docker system prune -af` without safeguards
3. **Makefiles**: A build target contains `git reset --hard`
4. **Dockerfiles**: A `RUN` command has dangerous operations

These commands sit dormant until executed—potentially in production, potentially causing data loss.

### The Solution

A pre-commit hook that scans staged files:

```bash
$ dcg install-hook

✓ Installed pre-commit hook at .git/hooks/pre-commit
✓ Created configuration at .dcg/hooks.toml

Configuration:
  Scan patterns: *.sh, *.bash, Makefile, *.mk, *.yml, *.yaml, Dockerfile*
  Check commit messages: true
  Fail on: error (warnings are advisory)

To customize: edit .dcg/hooks.toml
```

When committing:

```bash
$ git commit -m "Add deployment script"

┌─────────────────────────────────────────────────────────────────┐
│  DCG Pre-Commit Scan                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Scanning 3 staged files...                                     │
│                                                                 │
│  scripts/deploy.sh                                              │
│  ├─ Line 15: rm -rf ${DEPLOY_DIR}/*                             │
│  │  ├─ Pattern: core.filesystem:rm-rf-variable                  │
│  │  ├─ Risk: Unvalidated variable in recursive deletion         │
│  │  └─ Suggestion: Validate DEPLOY_DIR before deletion          │
│  │                                                              │
│  ├─ Line 28: git reset --hard origin/main                       │
│  │  ├─ Pattern: core.git:hard-reset                             │
│  │  ├─ Risk: Can permanently lose local commits                 │
│  │  └─ Suggestion: Use git fetch && git checkout instead        │
│  │                                                              │
│  └─ 2 issues found (1 error, 1 warning)                         │
│                                                                 │
│  .github/workflows/deploy.yml                                   │
│  └─ OK (no issues)                                              │
│                                                                 │
│  Makefile                                                       │
│  └─ OK (no issues)                                              │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  Summary: 1 error, 1 warning in 3 files                         │
│                                                                 │
│  ✗ Commit blocked due to errors.                                │
│                                                                 │
│  To commit anyway (not recommended):                            │
│    git commit --no-verify                                       │
│                                                                 │
│  To add an allowlist entry:                                     │
│    dcg allow --file scripts/deploy.sh:15 --reason "..."         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Configuration

```toml
# .dcg/hooks.toml

[pre_commit]
# File patterns to scan (gitignore-style globs)
scan_patterns = [
    "*.sh",
    "*.bash",
    "*.zsh",
    "Makefile",
    "*.mk",
    "*.yml",
    "*.yaml",
    "Dockerfile*",
    ".github/**/*.yml",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "*.tf",  # Terraform
]

# Patterns to exclude
exclude_patterns = [
    "vendor/**",
    "node_modules/**",
    "**/test/**",  # Exclude test directories
]

# Severity threshold for blocking commit
# Options: "error", "warning", "none" (advisory only)
fail_on = "error"

# Check commit message for dangerous patterns
check_commit_message = true

# Maximum file size to scan (bytes)
max_file_size = 1048576  # 1MB

# Show suggestions for fixing issues
show_suggestions = true

# Run in parallel (number of threads, 0 = auto)
parallel = 0
```

### File Type Detection

DCG detects the language/format of each file to apply appropriate scanning:

| File Pattern | Language | Scan Strategy |
|--------------|----------|---------------|
| `*.sh`, `*.bash` | Bash | Full shell command scanning |
| `Makefile`, `*.mk` | Make | Scan recipe lines (after tabs) |
| `*.yml`, `*.yaml` | YAML | Scan `run:`, `script:`, `command:` values |
| `Dockerfile*` | Docker | Scan `RUN`, `CMD`, `ENTRYPOINT` |
| `*.tf` | Terraform | Scan `provisioner` and `local-exec` blocks |
| `Jenkinsfile` | Groovy | Scan `sh`, `bash`, `bat` steps |

### Commit Message Scanning

Commit messages are also scanned:

```bash
$ git commit -m "Hotfix: run rm -rf / to clean up"

┌─────────────────────────────────────────────────────────────────┐
│  DCG Pre-Commit Scan                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ⚠️  Warning in commit message:                                 │
│                                                                 │
│  "Hotfix: run rm -rf / to clean up"                             │
│           └────────────┘                                        │
│           Pattern: core.filesystem:rm-rf-root                   │
│                                                                 │
│  This appears to reference a dangerous command.                 │
│  If this is intentional documentation, proceed with:            │
│    git commit --no-verify                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

Note: Commit message warnings don't block by default (configurable).

### Integration with Popular Hook Managers

#### Husky (Node.js)

```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "dcg scan --staged"
    }
  }
}
```

#### Lefthook

```yaml
# lefthook.yml
pre-commit:
  commands:
    dcg:
      run: dcg scan --staged
      fail_text: "DCG found dangerous patterns. Run 'dcg explain' for details."
```

#### Pre-commit (Python)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/anthropics/dcg
    rev: v0.2.0
    hooks:
      - id: dcg-scan
        name: DCG Security Scan
        entry: dcg scan --staged
        language: system
        pass_filenames: false
```

### CLI Commands

```bash
# Install hook directly
$ dcg install-hook
$ dcg install-hook --manager husky
$ dcg install-hook --manager lefthook

# Scan staged files manually
$ dcg scan --staged

# Scan specific files
$ dcg scan scripts/deploy.sh Makefile

# Scan entire directory
$ dcg scan --recursive ./scripts

# Scan with different severity threshold
$ dcg scan --staged --fail-on warning

# Output as JSON (for CI integration)
$ dcg scan --staged --format json

# Fix mode (interactive, where possible)
$ dcg scan --staged --fix
```

### Fix Mode

For some patterns, DCG can suggest or apply fixes:

```bash
$ dcg scan --staged --fix

scripts/deploy.sh:15
  - rm -rf ${DEPLOY_DIR}/*
  + if [ -n "${DEPLOY_DIR}" ] && [ -d "${DEPLOY_DIR}" ]; then
  +   rm -rf "${DEPLOY_DIR:?}"/*
  + fi

Apply this fix? [y/N/e(xplain)]
```

### Technical Design

#### New Module: `src/scan.rs`

```rust
use std::path::Path;

#[derive(Debug)]
pub struct ScanResult {
    pub file: PathBuf,
    pub issues: Vec<ScanIssue>,
}

#[derive(Debug)]
pub struct ScanIssue {
    pub line: usize,
    pub column: usize,
    pub severity: Severity,
    pub pattern: PatternMatch,
    pub line_content: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

pub struct Scanner {
    config: ScanConfig,
    allowlist: Allowlist,
}

impl Scanner {
    /// Scan a single file.
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult, ScanError> {
        let content = std::fs::read_to_string(path)?;
        let language = detect_language(path);
        let commands = extract_commands(&content, language);

        let mut issues = Vec::new();
        for (line_num, command) in commands {
            if let Decision::Deny { pattern, reason } = check_command(&command) {
                issues.push(ScanIssue {
                    line: line_num,
                    column: 0,
                    severity: pattern.severity(),
                    pattern: pattern,
                    line_content: command.clone(),
                    suggestion: get_suggestion(&pattern),
                });
            }
        }

        Ok(ScanResult { file: path.to_path_buf(), issues })
    }

    /// Scan all staged files in git.
    pub fn scan_staged(&self) -> Result<Vec<ScanResult>, ScanError> {
        let staged_files = git_staged_files()?;
        let filtered = self.filter_files(&staged_files);

        filtered
            .par_iter()  // Parallel scanning with rayon
            .map(|path| self.scan_file(path))
            .collect()
    }
}

/// Extract executable commands from file content based on language.
fn extract_commands(content: &str, language: Language) -> Vec<(usize, String)> {
    match language {
        Language::Bash => extract_bash_commands(content),
        Language::Makefile => extract_makefile_recipes(content),
        Language::Yaml => extract_yaml_commands(content),
        Language::Dockerfile => extract_dockerfile_commands(content),
        // ...
    }
}
```

### Implementation Phases

**Phase 1: Core Scanner (2-3 days)**
- File scanning with pattern matching
- Language detection and command extraction
- Basic output formatting

**Phase 2: Git Integration (1-2 days)**
- `--staged` flag for scanning staged files
- Hook installation (`dcg install-hook`)
- Commit message scanning

**Phase 3: Hook Manager Integration (1-2 days)**
- Husky configuration generation
- Lefthook configuration generation
- pre-commit (Python) hook definition

**Phase 4: Advanced Features (2-3 days)**
- Parallel scanning with rayon
- Fix mode for simple patterns
- JSON output for CI integration
- Allowlist for file:line entries

---

## 4. Comprehensive Test Infrastructure

### Overview

A robust testing strategy using property-based testing (proptest) to discover edge cases and fuzzing (cargo-fuzz) to find crashes, ensuring DCG is reliable under all conditions.

### The Problem It Solves

Security tools must be reliable. A crash, panic, or incorrect result in DCG could:

1. **Allow dangerous commands**: A parsing bug might miss a destructive pattern
2. **Block safe commands**: A regex bug might match too broadly
3. **Crash and fail open**: A panic might cause the hook to exit non-zero, allowing the command

Current testing (unit tests, E2E tests) catches known cases but misses:
- Edge cases with unusual input (unicode, long strings, special characters)
- Boundary conditions (empty strings, exactly 1MB files, etc.)
- Unexpected combinations of patterns
- Parser bugs with malformed input

### The Solution

#### Property-Based Testing with proptest

Define invariants that must hold for all inputs:

```rust
use proptest::prelude::*;

proptest! {
    /// Normalization is idempotent: normalizing twice gives same result as once.
    #[test]
    fn normalization_is_idempotent(cmd in ".*") {
        let once = normalize_command(&cmd);
        let twice = normalize_command(&once);
        prop_assert_eq!(once, twice, "Normalization should be idempotent");
    }

    /// Quick reject is consistent with full check for non-matching commands.
    #[test]
    fn quick_reject_consistency(cmd in "[a-z]+") {
        // Commands without dangerous keywords should be rejected quickly
        // and also allowed by full check
        if global_quick_reject(&cmd) == QuickRejectResult::Skip {
            let decision = check_command(&cmd);
            prop_assert!(
                matches!(decision, Decision::Allow),
                "Quick-rejected command should also be allowed by full check"
            );
        }
    }

    /// No command causes a panic.
    #[test]
    fn no_panics(cmd in ".*") {
        // This should never panic, regardless of input
        let _ = std::panic::catch_unwind(|| {
            check_command(&cmd)
        });
    }

    /// Known-safe commands are always allowed.
    #[test]
    fn safe_commands_allowed(cmd in safe_command_strategy()) {
        let decision = check_command(&cmd);
        prop_assert!(
            matches!(decision, Decision::Allow),
            "Safe command was incorrectly blocked: {}", cmd
        );
    }

    /// Known-dangerous commands are always blocked.
    #[test]
    fn dangerous_commands_blocked(cmd in dangerous_command_strategy()) {
        let decision = check_command(&cmd);
        prop_assert!(
            matches!(decision, Decision::Deny { .. }),
            "Dangerous command was incorrectly allowed: {}", cmd
        );
    }

    /// Decision is deterministic: same input always gives same output.
    #[test]
    fn deterministic_decision(cmd in ".*") {
        let result1 = check_command(&cmd);
        let result2 = check_command(&cmd);
        prop_assert_eq!(
            std::mem::discriminant(&result1),
            std::mem::discriminant(&result2),
            "Decision should be deterministic"
        );
    }
}
```

#### Custom Generators

```rust
/// Generate commands that are known to be safe.
fn safe_command_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Simple safe commands
        Just("git status".to_string()),
        Just("git log".to_string()),
        Just("git diff".to_string()),
        Just("ls -la".to_string()),
        Just("pwd".to_string()),

        // Parameterized safe commands
        "[a-z]{1,10}".prop_map(|name| format!("git checkout -b {}", name)),
        "[a-z]{1,20}".prop_map(|msg| format!("git commit -m \"{}\"", msg)),

        // Safe rm variants
        "/tmp/[a-z]{1,10}".prop_map(|path| format!("rm -rf {}", path)),
    ]
}

/// Generate commands that are known to be dangerous.
fn dangerous_command_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Hard reset variants
        Just("git reset --hard".to_string()),
        "HEAD~[0-9]{1,2}".prop_map(|ref_| format!("git reset --hard {}", ref_)),
        "[a-z]{1,10}".prop_map(|branch| format!("git reset --hard origin/{}", branch)),

        // Force push variants
        Just("git push --force".to_string()),
        Just("git push -f origin main".to_string()),

        // Dangerous rm variants
        Just("rm -rf /".to_string()),
        Just("rm -rf ~".to_string()),
        Just("rm -rf .".to_string()),
        "\\$[A-Z]{1,10}".prop_map(|var| format!("rm -rf {}", var)),
    ]
}

/// Generate edge-case inputs.
fn edge_case_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Empty and whitespace
        Just("".to_string()),
        Just(" ".to_string()),
        Just("\t\n\r".to_string()),

        // Unicode
        "\\p{L}{1,100}".prop_map(|s| format!("git commit -m \"{}\"", s)),

        // Very long commands
        ".{10000,20000}",

        // Special characters
        "[\\x00-\\x1f\\x7f-\\xff]{1,100}",

        // Nested quotes
        Just("git commit -m \"foo \\\"bar\\\" baz\"".to_string()),

        // Command injection attempts
        Just("git status; rm -rf /".to_string()),
        Just("git status && rm -rf /".to_string()),
        Just("git status | rm -rf /".to_string()),
        Just("$(rm -rf /)".to_string()),
        Just("`rm -rf /`".to_string()),
    ]
}
```

#### Fuzzing with cargo-fuzz

```rust
// fuzz/fuzz_targets/check_command.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use destructive_command_guard::check_command;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Should never panic
        let _ = check_command(s);
    }
});
```

```rust
// fuzz/fuzz_targets/parse_heredoc.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use destructive_command_guard::heredoc::parse_heredoc;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Should never panic
        let _ = parse_heredoc(s);
    }
});
```

```rust
// fuzz/fuzz_targets/json_input.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use destructive_command_guard::hook::parse_hook_input;

fuzz_target!(|data: &[u8]| {
    // Should handle any input gracefully
    let _ = parse_hook_input(data);
});
```

#### Regression Test Corpus

Maintain a corpus of known edge cases:

```
tests/corpus/
├── false_positives/
│   ├── bd_create_description.txt     # bd create --description="rm -rf example"
│   ├── git_commit_message.txt        # git commit -m "fix rm -rf bug"
│   ├── grep_pattern.txt              # rg "rm -rf" src/
│   └── echo_example.txt              # echo "Example: git reset --hard"
├── true_positives/
│   ├── rm_rf_root.txt                # rm -rf /
│   ├── git_reset_hard.txt            # git reset --hard HEAD~5
│   └── force_push_main.txt           # git push --force origin main
├── edge_cases/
│   ├── unicode_command.txt           # git commit -m "修复问题"
│   ├── very_long_command.txt         # ls [repeated 10000 times]
│   ├── null_bytes.txt                # git\x00status
│   └── nested_quotes.txt             # git commit -m "foo \"bar\" baz"
└── bypass_attempts/
    ├── semicolon_injection.txt       # git status; rm -rf /
    ├── pipe_injection.txt            # git status | rm -rf /
    ├── subshell_injection.txt        # $(rm -rf /)
    └── backtick_injection.txt        # `rm -rf /`
```

Each file contains a command that is tested for correct handling:

```rust
#[test]
fn test_false_positive_corpus() {
    for entry in glob("tests/corpus/false_positives/*.txt").unwrap() {
        let path = entry.unwrap();
        let command = std::fs::read_to_string(&path).unwrap().trim().to_string();
        let decision = check_command(&command);
        assert!(
            matches!(decision, Decision::Allow),
            "False positive not fixed: {} in {:?}",
            command,
            path
        );
    }
}

#[test]
fn test_true_positive_corpus() {
    for entry in glob("tests/corpus/true_positives/*.txt").unwrap() {
        let path = entry.unwrap();
        let command = std::fs::read_to_string(&path).unwrap().trim().to_string();
        let decision = check_command(&command);
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "True positive missed: {} in {:?}",
            command,
            path
        );
    }
}
```

### CI Integration

```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --all-features

  property-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --features proptest -- --ignored proptest

  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - run: cargo +nightly fuzz run check_command -- -max_total_time=300
      - run: cargo +nightly fuzz run parse_heredoc -- -max_total_time=300
      - run: cargo +nightly fuzz run json_input -- -max_total_time=300

  corpus-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test corpus
```

### Implementation Phases

**Phase 1: Property-Based Testing (2-3 days)**
- Add proptest to dev-dependencies
- Define core invariants (idempotence, determinism, no panics)
- Create generators for safe/dangerous/edge-case commands

**Phase 2: Fuzzing Setup (1-2 days)**
- Set up cargo-fuzz with fuzz targets
- Create targets for each parser/entry point
- Add to CI with time-limited runs

**Phase 3: Regression Corpus (1-2 days)**
- Create corpus directory structure
- Populate with known edge cases
- Add corpus-based tests

**Phase 4: CI Integration (1 day)**
- Add GitHub Actions workflows
- Configure fuzzing in CI
- Set up artifact collection for failures

---

## 5. GitHub Action for CI/CD Protection

### Overview

A GitHub Action that scans pull requests for dangerous patterns in scripts, configs, and other files, providing visibility to reviewers and optionally blocking merge.

### The Problem It Solves

Even with local hooks, dangerous patterns can enter the codebase:

1. **Developers skip hooks**: `git commit --no-verify` bypasses pre-commit
2. **External contributors**: Open-source contributors may not have DCG installed
3. **Direct GitHub edits**: Web-based editing bypasses all local hooks
4. **Automated tooling**: Bots and automation might not run local checks

CI is the last line of defense before code is merged.

### The Solution

A GitHub Action that runs on pull requests:

```yaml
# .github/workflows/dcg.yml
name: DCG Security Scan

on:
  pull_request:
    branches: [main, master]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write  # For PR comments

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for diff

      - name: DCG Security Scan
        uses: anthropics/dcg-action@v1
        with:
          # Severity threshold for failing the check
          fail_on: error  # or 'warning', 'none'

          # File patterns to scan
          scan_paths: |
            **/*.sh
            **/*.bash
            **/Makefile
            **/*.yml
            **/*.yaml
            **/Dockerfile*
            **/*.tf

          # Patterns to exclude
          exclude_paths: |
            vendor/**
            node_modules/**
            **/*.test.*

          # Post a comment on the PR with findings
          comment_on_pr: true

          # Show suggestions in the comment
          show_suggestions: true

          # GitHub token for API access
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

### PR Comment Output

When issues are found, the action posts a comment:

```markdown
## 🛡️ DCG Security Scan Results

**2 issues found** in this pull request.

### ❌ Errors (blocking)

<details>
<summary><code>scripts/deploy.sh</code> - 1 error</summary>

**Line 45:** `rm -rf ${DEPLOY_DIR}/*`

| | |
|---|---|
| **Pattern** | `core.filesystem:rm-rf-variable` |
| **Risk** | Unvalidated variable in recursive deletion could delete unintended files |
| **Suggestion** | Validate `DEPLOY_DIR` is set and within expected directory:<br><pre>if [ -z "${DEPLOY_DIR}" ]; then<br>  echo "DEPLOY_DIR not set" >&2<br>  exit 1<br>fi<br>rm -rf "${DEPLOY_DIR:?}"/*</pre> |

</details>

### ⚠️ Warnings (advisory)

<details>
<summary><code>.github/workflows/cleanup.yml</code> - 1 warning</summary>

**Line 23:** `docker system prune -af`

| | |
|---|---|
| **Pattern** | `containers.docker:system-prune-force` |
| **Risk** | Removes all unused images, containers, and volumes without confirmation |
| **Suggestion** | Consider `docker system prune --filter "until=24h"` to only remove old resources |

</details>

---

<details>
<summary>📚 How to resolve these issues</summary>

1. **Fix the code** - Address the issues identified above
2. **Add to allowlist** - If this is a false positive, add to `.dcg/allowlist.toml`:
   ```toml
   [[allow]]
   exact_command = "rm -rf ${DEPLOY_DIR}/*"
   reason = "Validated in deploy script"
   ```
3. **Request review** - If unsure, request review from a security-focused team member

</details>

---
*Scanned by [DCG](https://github.com/anthropics/dcg) v0.2.0 • [Documentation](https://docs.dcg.dev)*
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `fail_on` | Severity threshold: `error`, `warning`, `none` | `error` |
| `scan_paths` | Glob patterns for files to scan | `**/*.sh` etc. |
| `exclude_paths` | Glob patterns to exclude | `vendor/**` etc. |
| `comment_on_pr` | Post findings as PR comment | `true` |
| `show_suggestions` | Include fix suggestions | `true` |
| `github_token` | Token for API access | `${{ github.token }}` |
| `config_file` | Path to DCG config | `.dcg/config.toml` |
| `allowlist_file` | Path to allowlist | `.dcg/allowlist.toml` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `error_count` | Number of errors found |
| `warning_count` | Number of warnings found |
| `scanned_files` | Number of files scanned |
| `findings_json` | JSON array of all findings |

### Check Status Integration

The action creates a GitHub Check with detailed status:

```
DCG Security Scan
✗ 1 error, 1 warning

Details:
- scripts/deploy.sh: rm -rf with unvalidated variable
- .github/workflows/cleanup.yml: docker system prune without filter
```

This integrates with branch protection rules—repositories can require the DCG check to pass before merging.

### Diff-Only Scanning

By default, the action only scans files changed in the PR:

```yaml
- name: Get changed files
  id: changed
  run: |
    echo "files=$(git diff --name-only ${{ github.event.pull_request.base.sha }} ${{ github.sha }} | tr '\n' ' ')" >> $GITHUB_OUTPUT

- name: DCG Scan
  uses: anthropics/dcg-action@v1
  with:
    scan_paths: ${{ steps.changed.outputs.files }}
```

This keeps scans fast—only the changed code is analyzed.

### Technical Implementation

#### Action Structure

```
dcg-action/
├── action.yml           # Action definition
├── Dockerfile          # Container with DCG binary
├── entrypoint.sh       # Main script
├── src/
│   ├── index.ts        # TypeScript entry point
│   ├── scanner.ts      # Invokes DCG binary
│   ├── reporter.ts     # Formats output
│   └── github.ts       # GitHub API integration
├── package.json
└── README.md
```

#### action.yml

```yaml
name: 'DCG Security Scan'
description: 'Scan for dangerous command patterns in shell scripts and configs'
author: 'Anthropic'

branding:
  icon: 'shield'
  color: 'blue'

inputs:
  fail_on:
    description: 'Severity threshold for failing'
    required: false
    default: 'error'
  scan_paths:
    description: 'File patterns to scan (newline-separated)'
    required: false
    default: |
      **/*.sh
      **/*.bash
      **/Makefile
      **/*.yml
      **/*.yaml
      **/Dockerfile*
  exclude_paths:
    description: 'File patterns to exclude (newline-separated)'
    required: false
    default: |
      vendor/**
      node_modules/**
  comment_on_pr:
    description: 'Post comment on PR'
    required: false
    default: 'true'
  github_token:
    description: 'GitHub token for API access'
    required: true
    default: ${{ github.token }}

outputs:
  error_count:
    description: 'Number of errors found'
  warning_count:
    description: 'Number of warnings found'
  findings_json:
    description: 'JSON array of findings'

runs:
  using: 'docker'
  image: 'Dockerfile'
  args:
    - ${{ inputs.fail_on }}
    - ${{ inputs.scan_paths }}
    - ${{ inputs.exclude_paths }}
    - ${{ inputs.comment_on_pr }}
    - ${{ inputs.github_token }}
```

### Implementation Phases

**Phase 1: Core Action (2-3 days)**
- Docker container with DCG binary
- Basic scanning of changed files
- Exit code based on findings

**Phase 2: GitHub Integration (2-3 days)**
- PR comment posting
- Check status creation
- Findings formatting (markdown)

**Phase 3: Advanced Features (1-2 days)**
- Allowlist support
- Suggestion generation
- JSON output for further processing

**Phase 4: Documentation & Release (1 day)**
- README with examples
- GitHub Marketplace listing
- Version tagging

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)

| Task | Effort | Dependencies |
|------|--------|--------------|
| Explain mode core infrastructure | 3 days | None |
| Allowlist module | 2 days | None |
| Property-based test setup | 2 days | None |

### Phase 2: Core Features (Week 3-4)

| Task | Effort | Dependencies |
|------|--------|--------------|
| Explain mode CLI & formatting | 2 days | Explain core |
| Interactive learning mode | 3 days | Allowlist |
| Fuzzing targets | 2 days | None |
| Pre-commit scanner | 3 days | None |

### Phase 3: Integration (Week 5-6)

| Task | Effort | Dependencies |
|------|--------|--------------|
| Pre-commit hook installation | 2 days | Scanner |
| Hook manager integration | 2 days | Hook installation |
| GitHub Action core | 3 days | None |
| GitHub Action PR integration | 2 days | Action core |

### Phase 4: Polish (Week 7-8)

| Task | Effort | Dependencies |
|------|--------|--------------|
| Suggestions database | 2 days | Explain mode |
| Corpus-based regression tests | 2 days | Fuzzing |
| Documentation | 3 days | All features |
| Release & marketing | 2 days | Documentation |

### Total Estimated Effort

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| Foundation | 2 weeks | Explain mode, allowlist, proptest |
| Core Features | 2 weeks | Learning mode, fuzzing, scanner |
| Integration | 2 weeks | Pre-commit hooks, GitHub Action |
| Polish | 2 weeks | Suggestions, docs, release |
| **Total** | **8 weeks** | Full feature set |

---

## Success Metrics

### User Experience Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| False positive rate | <5% | Telemetry (opt-in) |
| Time to understand block | <30 seconds | User testing |
| Time to resolve false positive | <2 minutes | User testing |
| User satisfaction (NPS) | >50 | Survey |

### Reliability Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Crash rate | 0% | Crash reporting |
| Test coverage | >90% | Coverage tools |
| Property test failures | 0 | CI |
| Fuzz test crashes | 0 | CI |

### Adoption Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Projects with allowlist | 30% of users | File detection |
| Pre-commit hook installs | 20% of users | Install tracking |
| GitHub Action usage | 1000+ repos | Marketplace stats |
| Community contributions | 10+ pattern packs | GitHub |

---

## Appendix: Ideas Not Selected

The following ideas were considered but not included in the top 5:

| Idea | Reason Not Selected |
|------|---------------------|
| Bloom filter pre-check | Marginal gain over memchr, premature optimization |
| Hot-reloading config | DCG is invoked per-command, not long-running |
| Shell completions | DCG is usually invoked by Claude Code, not typed |
| VS Code extension | Redundant with Claude Code hook |
| Cross-command context | Complex, requires statefulness, higher false positive risk |
| ML-based detection | Adds latency and complexity, regex works well |
| Prometheus metrics | DCG is CLI, not long-running service |
| Community pattern packs | Valuable but requires significant infrastructure (registry, trust model) |
| Semantic intent analysis | Too vague, hard to implement reliably |
| Project type detection | Nice personalization but adds complexity |

These ideas may be revisited in future versions as the project matures.

---

## Conclusion

The five improvements outlined in this document form a cohesive strategy to make DCG:

1. **Transparent** — Explain mode shows exactly why decisions are made
2. **Customizable** — Allowlists let users tailor behavior to their projects
3. **Comprehensive** — Pre-commit hooks protect the codebase, not just execution
4. **Reliable** — Property-based testing and fuzzing ensure robustness
5. **Scalable** — GitHub Action extends protection to entire teams

Together, these improvements transform DCG from a reactive blocker into a proactive security layer that users understand, trust, and rely on.

---

*Document generated by Claude Opus 4.5 on 2026-01-07*
