# Agent-Friendliness Report: Destructive Command Guard (dcg)

**Bead ID**: bd-dpr
**Date**: 2026-01-25
**Agent**: Claude Opus 4.5

## Executive Summary

**Status: MODERATE AGENT-FRIENDLINESS MATURITY**

dcg has comprehensive robot mode support with JSON output across most commands:
- `--robot` flag with silent stderr and JSON stdout
- `--format json` on most subcommands
- `DCG_ROBOT` and `DCG_FORMAT` environment variables
- Well-structured JSON with schema versioning

However, it lacks:
- TOON output format (not integrated)
- AGENTS.md documentation file
- Some output format gaps (sarif alias but no actual SARIF)

## 1. Current State Assessment

### 1.1 Robot Mode Support

| Feature | Status | Details |
|---------|--------|---------|
| `--robot` flag | YES | Global flag, JSON output + silent stderr |
| `--format` flag | YES | pretty, json, jsonl, compact |
| `DCG_FORMAT` env | YES | Set default format via environment |
| `DCG_ROBOT` env | YES | Enable robot mode via environment |
| `--no-color` flag | YES | Disable colored output |
| `DCG_NO_COLOR` env | YES | Disable colors via environment |
| Exit codes | YES | Documented (0=allow, 1=deny, 2=warn, 3=config, 4=parse, 5=io) |

### 1.2 Output Formats

| Format | Description |
|--------|-------------|
| `pretty` | Human-readable colored output (default) |
| `json` | Structured JSON output |
| `jsonl` | JSON Lines for streaming/batch |
| `compact` | Compact single-line output |

**Note**: No TOON format support currently.

### 1.3 Commands with JSON Support

| Command | JSON | --robot | Notes |
|---------|------|---------|-------|
| `dcg doctor` | YES | - | Uses `--format json`, schema_version=1 |
| `dcg test` | YES | YES | Full decision info with rule_id, pack_id |
| `dcg explain` | YES | - | Detailed trace with steps, match, suggestions |
| `dcg packs` | YES | - | Pack list with enabled status |
| `dcg scan` | YES | YES | File scanning with SARIF-like output |
| `dcg simulate` | YES | - | Policy simulation results |
| `dcg history` | YES | - | Command history queries |
| `dcg suggest-allowlist` | YES | - | Allowlist suggestions |
| `dcg stats` | YES | - | Aggregated statistics |
| `dcg hook --batch` | YES | - | JSONL batch processing |

### 1.4 JSON Output Structure

The `dcg test` output shows excellent structure:
```json
{
  "command": "git reset --hard",
  "decision": "deny",
  "rule_id": "core.git:reset-hard",
  "pack_id": "core.git",
  "pattern_name": "reset-hard",
  "reason": "git reset --hard destroys uncommitted changes...",
  "source": "pack",
  "matched_span": [0, 16],
  "agent": {
    "detected": "unknown",
    "trust_level": "medium",
    "detection_method": "none"
  }
}
```

The `dcg explain` output includes:
- `schema_version`: Version for compatibility
- `steps`: Decision pipeline trace with durations
- `match`: Full pattern match details with explanation
- `suggestions`: Actionable alternatives

### 1.5 MCP Server Support

dcg includes an MCP server mode (`dcg mcp-server`) exposing:
- `check_command`: Evaluate a command
- `scan_file`: Scan files for destructive commands
- `explain_pattern`: Explain a dcg rule

This is excellent for direct agent integration without shell hooks.

## 2. Documentation Assessment

### 2.1 AGENTS.md

**Status**: MISSING

No AGENTS.md file exists in the repository.

### 2.2 README.md

Not assessed in this review.

### 2.3 --help Output

**Status**: GOOD

The `--help` output includes:
- Clear usage instructions
- Environment variables list
- Common blocked commands
- Configuration examples

## 3. Scorecard

| Dimension | Score (1-5) | Notes |
|-----------|-------------|-------|
| Documentation | 3 | No AGENTS.md, good --help |
| CLI Ergonomics | 5 | Excellent subcommand structure |
| Robot Mode | 4 | --robot, --format json, env vars |
| Error Handling | 4 | Structured errors, semantic exit codes |
| Consistency | 4 | OutputFormat enum, schema versioning |
| Zero-shot Usability | 4 | Good --help, examples in help |
| **Overall** | **4.0** | Good maturity, needs TOON + AGENTS.md |

## 4. Gap Analysis

### 4.1 Missing TOON Integration

dcg does not have `toon_rust` as a dependency and lacks TOON output format:
- No `OutputFormat::Toon` variant
- No `--format toon` option
- No `TOON_DEFAULT_FORMAT` environment variable

### 4.2 Missing AGENTS.md

No agent-specific documentation exists. Should include:
- Command quick reference for agents
- JSON output schemas
- Exit code semantics
- MCP server usage

### 4.3 OutputFormat Inconsistency

The CLI advertises `DCG_FORMAT=text|json|sarif` but actual SARIF format is not implemented - `sarif` is just an alias for `json`.

## 5. TOON Integration Status

**Status: NOT INTEGRATED**

To integrate TOON:
1. Add `toon_rust = { path = "../toon_rust" }` to Cargo.toml
2. Add `Toon` variant to `OutputFormat` enum in cli.rs
3. Implement TOON encoding in output formatting paths
4. Add `--format toon` flag option

## 6. Recommendations

### 6.1 High Priority (P1)

1. **Create AGENTS.md** - Document agent usage patterns, JSON schemas, exit codes
2. **Add TOON integration** - Add toon_rust dependency and OutputFormat::Toon

### 6.2 Medium Priority (P2)

1. Add `--schema` flag to emit JSON Schema for command outputs
2. Document MCP server tools more explicitly for agents
3. Add `--capabilities` command for feature discovery

### 6.3 Low Priority (P3)

1. Implement actual SARIF format output (not just alias)
2. Add docs/agent/QUICKSTART.md

## 7. Baseline Artifacts

Captured in `/dp/destructive_command_guard/agent_baseline/`:
- `help.txt` - Full --help output
- `doctor.json` - Doctor command JSON output
- `test_deny.json` - Test command deny response
- `explain.json` - Explain command full trace

## 8. Conclusion

dcg is moderately agent-friendly with:
- Comprehensive robot mode support
- JSON output across most commands
- MCP server for direct integration
- Schema versioning in outputs

Key gaps are:
- Missing TOON integration (unlike rch, pt)
- Missing AGENTS.md documentation
- Some format inconsistencies

Score: **4.0/5** - Good maturity, specific improvements needed.

---
*Generated by Claude Opus 4.5 during bd-dpr execution*
