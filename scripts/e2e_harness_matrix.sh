#!/usr/bin/env bash
# e2e_harness_matrix.sh — real-binary, no-mock conformance for every shipped
# agent hook protocol or native extension bridge.
#
# WHY THIS EXISTS
# ---------------
# dcg's value is entirely in what a *harness* does with its output. A change
# that keeps `cargo test` green can still break every user if the JSON shape,
# the exit code, or the stream a harness reads changes. The unit tests call
# Rust functions; this suite spawns the real binary with the real stdin
# payload each harness actually sends and asserts on the exact bytes it emits.
#
# Every case is triple-asserted: the decision field the harness parses, the
# exit code it inspects, and the stream separation (machine output on stdout,
# human output on stderr) it depends on. No mocks, no library calls.
#
# Usage:
#   scripts/e2e_harness_matrix.sh [--binary PATH] [--json] [--verbose]
#
# Exit: 0 all passed, 1 any failure, 2 usage/setup error.
set -uo pipefail

BINARY=""
JSON_OUTPUT=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --json) JSON_OUTPUT=true; shift ;;
    --verbose|-v) VERBOSE=true; shift ;;
    --help|-h)
      sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$BINARY" ]]; then
  target_dir="${CARGO_TARGET_DIR:-target}"
  BINARY="$target_dir/release/dcg"
fi
if [[ ! -x "$BINARY" ]]; then
  echo "error: dcg binary not found or not executable: $BINARY" >&2
  echo "hint: cargo build --release, or pass --binary /abs/path/to/dcg" >&2
  exit 2
fi
BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"

command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 2; }

# Hermetic environment: an empty HOME and no ambient DCG_* so the suite tests
# SHIPPED defaults, never the operator's config. Also keeps dcg's self-heal
# from rewriting the real ~/.claude/settings.json during a test run.
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/dcg-harness-matrix.XXXXXX")"
mkdir -p "$SANDBOX/home" "$SANDBOX/home/.config" "$SANDBOX/work"
# Hook mode: the JSON payload arrives on STDIN. Every argument to this helper
# is an extra KEY=VALUE environment assignment layered over the hermetic base.
run_dcg() {
  ( cd "$SANDBOX/work" && env -i \
      PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
      HOME="$SANDBOX/home" USERPROFILE="$SANDBOX/home" \
      XDG_CONFIG_HOME="$SANDBOX/home/.config" \
      TMPDIR="${TMPDIR:-/tmp}" \
      DCG_SELF_HEAL_HOOK=0 DCG_HISTORY_DISABLED=1 \
      "$@" "$BINARY" )
}

# CLI mode: arguments are dcg subcommand/flags, same hermetic environment.
run_dcg_cli() {
  ( cd "$SANDBOX/work" && env -i \
      PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
      HOME="$SANDBOX/home" USERPROFILE="$SANDBOX/home" \
      XDG_CONFIG_HOME="$SANDBOX/home/.config" \
      TMPDIR="${TMPDIR:-/tmp}" \
      DCG_SELF_HEAL_HOOK=0 DCG_HISTORY_DISABLED=1 \
      "$BINARY" "$@" )
}

PASS=0; FAIL=0
declare -a FAILURES=()

# Millisecond clock. `date +%s%N` is a GNU extension (BSD date yields a literal
# "N"), so fall back to python3 and finally to "no timing" rather than emitting
# garbage numbers.
if _probe="$(date +%s%N 2>/dev/null)" && [[ "$_probe" != *N* && ${#_probe} -ge 16 ]]; then
  now_ms() { echo $(( $(date +%s%N) / 1000000 )); }
elif command -v python3 >/dev/null 2>&1; then
  now_ms() { python3 -c 'import time; print(time.monotonic_ns() // 1000000)'; }
else
  now_ms() { echo ""; }
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"

log_json() {
  $JSON_OUTPUT || return 0
  printf '%s\n' "$1"
}

# Per-case wall-clock, set by assert_case so failures carry timing context.
CASE_MS=""

report() {
  local status="$1" harness="$2" case_name="$3" detail="${4:-}"
  if [[ "$status" == pass ]]; then
    PASS=$((PASS + 1))
    $JSON_OUTPUT || printf '  \033[0;32m✓\033[0m %-14s %s\n' "$harness" "$case_name"
  else
    FAIL=$((FAIL + 1))
    FAILURES+=("$harness/$case_name: $detail")
    $JSON_OUTPUT || printf '  \033[0;31m✗\033[0m %-14s %s\n     %s\n' "$harness" "$case_name" "$detail"
  fi
  # Structured event: every field a CI reader needs to triage without a repro
  # — which run, which binary, which case, how long it took, and why it failed.
  log_json "$(jq -nc --arg r "$RUN_ID" --arg h "$harness" --arg c "$case_name" \
    --arg s "$status" --arg d "$detail" --arg ms "$CASE_MS" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{ts:$ts,run_id:$r,event:"case",harness:$h,case:$c,status:$s,detail:$d}
     + (if $ms == "" then {} else {duration_ms:($ms|tonumber)} end)')"
  CASE_MS=""
}

# ---------------------------------------------------------------------------
# Core assertion: run a payload, then check decision JSON + exit code +
# stream separation all at once.
#
#   assert_case <harness> <case> <payload> <expect: deny|allow>
#               <jq filter yielding the harness's decision value>
#               <expected decision value>
# ---------------------------------------------------------------------------
assert_case() {
  local harness="$1" case_name="$2" payload="$3" expect="$4" filter="$5" want="$6"
  shift 6
  local out_file err_file rc stdout_data stderr_data
  out_file="$(mktemp "$SANDBOX/out.XXXXXX")"
  err_file="$(mktemp "$SANDBOX/err.XXXXXX")"

  local started ended
  started="$(now_ms)"
  printf '%s' "$payload" | run_dcg "$@" >"$out_file" 2>"$err_file"
  rc=$?
  ended="$(now_ms)"
  [[ -n "$started" && -n "$ended" ]] && CASE_MS=$((ended - started))
  stdout_data="$(cat "$out_file")"
  stderr_data="$(cat "$err_file")"

  $VERBOSE && { echo "    payload: ${payload:0:120}"; echo "    rc=$rc stdout=${#stdout_data}B stderr=${#stderr_data}B"; }

  # Every shipped protocol exits 0: a non-zero exit is interpreted as a hook
  # *failure* (fail-open) by Codex/Hermes/agy rather than as a block.
  if [[ "$rc" -ne 0 ]]; then
    report fail "$harness" "$case_name" "exit code $rc (must be 0; non-zero reads as hook failure)"
    return
  fi

  if [[ "$expect" == allow ]]; then
    if [[ -n "$stdout_data" ]]; then
      report fail "$harness" "$case_name" "allow must emit empty stdout, got: ${stdout_data:0:160}"
      return
    fi
    report pass "$harness" "$case_name"
    return
  fi

  if [[ -z "$stdout_data" ]]; then
    report fail "$harness" "$case_name" "deny emitted EMPTY stdout — harness would let the command run"
    return
  fi
  if ! printf '%s' "$stdout_data" | jq -e . >/dev/null 2>&1; then
    report fail "$harness" "$case_name" "stdout is not valid JSON: ${stdout_data:0:160}"
    return
  fi
  local got
  got="$(printf '%s' "$stdout_data" | jq -r "$filter" 2>/dev/null)"
  if [[ "$got" != "$want" ]]; then
    report fail "$harness" "$case_name" "decision field: want '$want', got '$got' (filter $filter)"
    return
  fi
  # Human-facing output belongs on stderr and must never pollute stdout.
  if [[ -z "$stderr_data" ]]; then
    report fail "$harness" "$case_name" "deny produced no stderr warning (human visibility lost)"
    return
  fi
  report pass "$harness" "$case_name"
}

# Assert a field is ABSENT from the denial payload (Codex rejects unknowns).
assert_field_absent() {
  local harness="$1" case_name="$2" payload="$3" field="$4"
  local stdout_data
  stdout_data="$(printf '%s' "$payload" | run_dcg 2>/dev/null)"
  if printf '%s' "$stdout_data" | jq -e "$field" >/dev/null 2>&1; then
    report fail "$harness" "$case_name" "field $field present; strict parsers reject unknown fields"
  else
    report pass "$harness" "$case_name"
  fi
}

# Assert the exact private robot-mode contract used by Oh My Pi. OMP passes the
# raw command on stdin, requests the compact envelope, and maps dcg's exit
# status plus these exact bytes back to ExtensionAPI's blocking result.
assert_omp_bridge_case() {
  local harness="$1" case_name="$2" command="$3" expected_rc="$4" expected_stdout="$5"
  local stdout_file="$SANDBOX/${harness}-${case_name}.stdout"
  local stderr_file="$SANDBOX/${harness}-${case_name}.stderr"
  local start end
  start="$(now_ms)"
  printf '%s' "$command" | run_dcg_cli --robot test --stdin \
    --agent omp --dialect posix --format json --omp-bridge-output \
    >"$stdout_file" 2>"$stderr_file"
  local rc=$?
  end="$(now_ms)"
  CASE_MS=""
  [[ -n "$start" && -n "$end" ]] && CASE_MS=$((end - start))

  local stdout_data stdout_bytes expected_bytes
  stdout_data="$(cat "$stdout_file")"
  stdout_bytes="$(wc -c <"$stdout_file" | tr -d '[:space:]')"
  expected_bytes=$((${#expected_stdout} + 1))
  if [[ $rc -ne $expected_rc ]]; then
    report fail "$harness" "$case_name" "exit $rc, want $expected_rc"
  elif [[ -s "$stderr_file" ]]; then
    report fail "$harness" "$case_name" "private OMP bridge polluted stderr"
  elif [[ "$stdout_data" != "$expected_stdout" || "$stdout_bytes" -ne "$expected_bytes" ]]; then
    report fail "$harness" "$case_name" \
      "compact stdout mismatch: got ${stdout_bytes}B '${stdout_data:0:200}', want ${expected_bytes}B '$expected_stdout'"
  else
    report pass "$harness" "$case_name"
  fi
}

# The compact OMP envelope intentionally omits attribution. Retain one ordinary
# robot assertion so `--agent omp` cannot silently stop selecting OMP policy.
assert_omp_agent_attribution() {
  local stdout_file="$SANDBOX/omp-attribution.stdout"
  local stderr_file="$SANDBOX/omp-attribution.stderr"
  printf '%s' "$ALLOW_CMD" | run_dcg_cli --robot test --stdin \
    --agent omp --dialect posix --format json >"$stdout_file" 2>"$stderr_file"
  local rc=$? agent method
  agent="$(jq -r '.agent.detected // empty' "$stdout_file" 2>/dev/null)"
  method="$(jq -r '.agent.detection_method // empty' "$stdout_file" 2>/dev/null)"
  if [[ $rc -ne 0 ]]; then
    report fail omp agent-attribution "exit $rc, want 0"
  elif [[ "$agent" != "omp" || "$method" != "explicit" ]]; then
    report fail omp agent-attribution \
      "agent attribution '$agent'/'$method', want omp/explicit"
  elif [[ -s "$stderr_file" ]]; then
    report fail omp agent-attribution "ordinary robot output polluted stderr"
  else
    report pass omp agent-attribution
  fi
}

DENY_CMD='git reset --hard'
ALLOW_CMD='git status'

$JSON_OUTPUT || echo "dcg harness protocol matrix — binary: $BINARY"
$JSON_OUTPUT || echo
# Run header: provenance for anyone triaging a failure from CI logs alone.
log_json "$(jq -nc --arg r "$RUN_ID" --arg b "$BINARY" \
  --arg v "$(run_dcg_cli --version 2>&1 | head -1 | tr -d '\r')" \
  --arg host "$(uname -s 2>/dev/null)/$(uname -m 2>/dev/null)" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{ts:$ts,run_id:$r,event:"run_start",suite:"harness_matrix",
    binary:$b,dcg_version:$v,host:$host}')"

# --- Claude Code (also VS Code Copilot Chat, Cursor bridge) ----------------
$JSON_OUTPUT || echo "Claude Code / VS Code Copilot Chat"
CLAUDE_DENY=$(jq -nc --arg c "$DENY_CMD" '{tool_name:"Bash",tool_input:{command:$c}}')
CLAUDE_ALLOW=$(jq -nc --arg c "$ALLOW_CMD" '{tool_name:"Bash",tool_input:{command:$c}}')
assert_case claude-code deny "$CLAUDE_DENY" deny \
  '.hookSpecificOutput.permissionDecision' deny
assert_case claude-code allow "$CLAUDE_ALLOW" allow '.' ''
# The PowerShell shell tool is platform-sensitive by design: windows.filesystem
# is default-ON on Windows and opt-in elsewhere. Assert the behavior for the
# host we are actually running on rather than assuming Unix.
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) WIN_PACK_EXPECT=deny ;;
  *) WIN_PACK_EXPECT=allow ;;
esac
if [[ "$WIN_PACK_EXPECT" == deny ]]; then
  assert_case claude-code powershell-tool-windows-default-packs \
    "$(jq -nc --arg c 'Remove-Item -Recurse -Force C:\\src' '{tool_name:"PowerShell",tool_input:{command:$c}}')" \
    deny '.hookSpecificOutput.permissionDecision' deny
else
  assert_case claude-code powershell-tool-optin-on-unix \
    "$(jq -nc --arg c 'Remove-Item -Recurse -Force C:\\src' '{tool_name:"PowerShell",tool_input:{command:$c}}')" \
    allow '.' ''
fi
# The agent-facing metadata contract other tools key on:
for field in ruleId packId severity; do
  got="$(printf '%s' "$CLAUDE_DENY" | run_dcg 2>/dev/null | jq -r ".hookSpecificOutput.$field // empty")"
  if [[ -n "$got" ]]; then report pass claude-code "metadata:$field"
  else report fail claude-code "metadata:$field" "missing $field in denial (agents key allowlists on it)"; fi
done
got="$(printf '%s' "$CLAUDE_DENY" | run_dcg 2>/dev/null | jq -r '.hookSpecificOutput.hookEventName // empty')"
if [[ "$got" == "PreToolUse" ]]; then
  report pass claude-code hookEventName
else
  report fail claude-code hookEventName "want PreToolUse, got '$got'"
fi

# --- Codex CLI (strict parser: rejects unknown fields) ----------------------
$JSON_OUTPUT || echo "Codex CLI"
CODEX_DENY=$(jq -nc --arg c "$DENY_CMD" '{tool_name:"Bash",tool_input:{command:$c},turn_id:"turn_e2e_1"}')
CODEX_ALLOW=$(jq -nc --arg c "$ALLOW_CMD" '{tool_name:"Bash",tool_input:{command:$c},turn_id:"turn_e2e_2"}')
assert_case codex deny "$CODEX_DENY" deny '.hookSpecificOutput.permissionDecision' deny
assert_case codex allow "$CODEX_ALLOW" allow '.' ''
# Extended Claude-only fields MUST be absent/null for Codex's deny_unknown_fields.
assert_field_absent codex no-allowOnceCode "$CODEX_DENY" '.hookSpecificOutput.allowOnceCode | select(. != null)'
assert_field_absent codex no-remediation "$CODEX_DENY" '.hookSpecificOutput.remediation | select(. != null)'
assert_field_absent codex no-ruleId "$CODEX_DENY" '.hookSpecificOutput.ruleId | select(. != null)'
# Windows shells classify as Codex even without turn_id (issue #125).
assert_case codex deny-windows-shell \
  "$(jq -nc --arg c "$DENY_CMD" '{tool_name:"powershell",tool_input:{command:$c}}')" \
  deny '.hookSpecificOutput.permissionDecision' deny

# --- Gemini CLI -------------------------------------------------------------
$JSON_OUTPUT || echo "Gemini CLI"
GEMINI_DENY=$(jq -nc --arg c "$DENY_CMD" \
  '{hook_event_name:"BeforeTool",tool_name:"run_shell_command",tool_input:{command:$c}}')
GEMINI_ALLOW=$(jq -nc --arg c "$ALLOW_CMD" \
  '{hook_event_name:"BeforeTool",tool_name:"run_shell_command",tool_input:{command:$c}}')
assert_case gemini deny "$GEMINI_DENY" deny '.decision' deny
assert_case gemini allow "$GEMINI_ALLOW" allow '.' ''

# --- GitHub Copilot CLI -----------------------------------------------------
$JSON_OUTPUT || echo "GitHub Copilot CLI"
COPILOT_DENY=$(jq -nc --arg c "$DENY_CMD" \
  '{event:"preToolUse",tool_name:"bash",tool_args:{command:$c}}')
COPILOT_ALLOW=$(jq -nc --arg c "$ALLOW_CMD" \
  '{event:"preToolUse",tool_name:"bash",tool_args:{command:$c}}')
assert_case copilot deny "$COPILOT_DENY" deny '.permissionDecision' deny
assert_case copilot allow "$COPILOT_ALLOW" allow '.' ''

# --- Hermes Agent (decision:"block") ---------------------------------------
$JSON_OUTPUT || echo "Hermes Agent"
HERMES_DENY=$(jq -nc --arg c "$DENY_CMD" \
  '{hook_event_name:"pre_tool_call",tool_name:"terminal",tool_input:{command:$c}}')
HERMES_ALLOW=$(jq -nc --arg c "$ALLOW_CMD" \
  '{hook_event_name:"pre_tool_call",tool_name:"terminal",tool_input:{command:$c}}')
assert_case hermes deny "$HERMES_DENY" deny '.decision' block
assert_case hermes allow "$HERMES_ALLOW" allow '.' ''
# Hermes cross-version alternate keys must both be present.
got="$(printf '%s' "$HERMES_DENY" | run_dcg 2>/dev/null | jq -r '.action // empty')"
if [[ "$got" == "block" ]]; then
  report pass hermes alt-action-key
else
  report fail hermes alt-action-key "want action=block, got '$got'"
fi

# --- Grok (xAI): decision:"deny", camelCase wire shape ---------------------
$JSON_OUTPUT || echo "Grok (xAI)"
GROK_DENY=$(jq -nc --arg c "$DENY_CMD" \
  '{hookEventName:"pre_tool_use",toolName:"run_terminal_cmd",toolInput:{command:$c}}')
GROK_ALLOW=$(jq -nc --arg c "$ALLOW_CMD" \
  '{hookEventName:"pre_tool_use",toolName:"run_terminal_cmd",toolInput:{command:$c}}')
assert_case grok deny "$GROK_DENY" deny '.decision' deny
assert_case grok allow "$GROK_ALLOW" allow '.' ''

# --- Antigravity CLI (agy): nested toolCall envelope, decision:"block" -----
$JSON_OUTPUT || echo "Antigravity CLI (agy)"
AGY_DENY=$(jq -nc --arg c "$DENY_CMD" \
  '{toolCall:{name:"run_command",args:{CommandLine:$c}},conversationId:"conv_e2e",stepIdx:1}')
AGY_ALLOW=$(jq -nc --arg c "$ALLOW_CMD" \
  '{toolCall:{name:"run_command",args:{CommandLine:$c}},conversationId:"conv_e2e",stepIdx:2}')
assert_case agy deny "$AGY_DENY" deny '.decision' block
assert_case agy allow "$AGY_ALLOW" allow '.' ''

# --- Oh My Pi: native ExtensionAPI bridge over robot stdin ------------------
$JSON_OUTPUT || echo "Oh My Pi (omp)"
assert_omp_bridge_case omp deny "$DENY_CMD" 1 \
  '{"decision":"deny","reason":"git reset --hard destroys uncommitted changes. Use '\''git stash'\'' first.","rule_id":"core.git:reset-hard"}'
assert_omp_bridge_case omp allow "$ALLOW_CMD" 0 '{"decision":"allow"}'
assert_omp_agent_attribution

# --- Cross-cutting invariants ----------------------------------------------
$JSON_OUTPUT || echo "Cross-cutting invariants"

# Non-shell tools are never evaluated.
assert_case all non-shell-tool-ignored \
  "$(jq -nc '{tool_name:"Read",tool_input:{file_path:"/etc/passwd"}}')" allow '.' ''

# Unparseable input fails OPEN by default (documented contract), and the
# fail-closed opt-in must actually deny.
out="$(printf 'not json at all' | run_dcg 2>/dev/null)"; rc=$?
if [[ $rc -eq 0 && -z "$out" ]]; then
  report pass all malformed-fails-open
else
  report fail all malformed-fails-open "want silent allow, rc=$rc out='${out:0:80}'"
fi
out="$(printf 'not json at all' | run_dcg DCG_FAIL_CLOSED=1 2>/dev/null)"
if [[ -n "$out" ]]; then
  report pass all malformed-fail-closed-opt-in
else
  report fail all malformed-fail-closed-opt-in "DCG_FAIL_CLOSED=1 produced no denial"
fi

# BOM-prefixed valid input must still be evaluated (issue #160).
BOM_PAYLOAD="$(printf '\xef\xbb\xbf%s' "$CLAUDE_DENY")"
assert_case all bom-prefixed-still-denies "$BOM_PAYLOAD" deny \
  '.hookSpecificOutput.permissionDecision' deny

# DCG_BYPASS is the documented escape hatch.
assert_case all bypass-env "$CLAUDE_DENY" allow '.' '' DCG_BYPASS=1

# THE #245 REGRESSION GUARD, at the protocol layer: with the shipped default
# budget, ordinary commands must reach a real verdict — never the
# indeterminate ask/deny that a blown deadline produces.
$JSON_OUTPUT || echo "Latency-induced indeterminacy (#245 guard)"
for cmd in 'echo hi 2>/dev/null' 'cp report.txt backup.txt' 'rm ./scratch.txt' '[ -f x ]' 'ls -la'; do
  payload="$(jq -nc --arg c "$cmd" '{tool_name:"Bash",tool_input:{command:$c}}')"
  out="$(printf '%s' "$payload" | run_dcg 2>/dev/null)"
  if printf '%s' "$out" | grep -q 'could not complete safety evaluation'; then
    report fail latency "no-indeterminate: $cmd" \
      "stock budget produced an indeterminate verdict — this is the #245 outage"
  elif printf '%s' "$out" | jq -e '.hookSpecificOutput.permissionDecision == "ask"' >/dev/null 2>&1; then
    report fail latency "no-indeterminate: $cmd" "verdict was 'ask' (deadline exhausted)"
  else
    report pass latency "no-indeterminate: $cmd"
  fi
done

# The effective default budget must be what we ship, on a cold process with no
# user config. This is what silently regressed for every user in #245.
budget_line="$(run_dcg_cli config --format json 2>/dev/null)"
# Pin to the exact key. A loose regex also matches the heredoc extraction
# budget (`heredoc.timeout_ms`, 50ms), so a JSON reordering would silently
# make this gate compare against the wrong number.
effective_budget="$(printf '%s' "$budget_line" | jq -r '
  .general.hook_timeout_ms // empty | numbers' 2>/dev/null | head -1)"
# The number alone cannot distinguish the shipped budget from an operator's
# DCG_HOOK_TIMEOUT_MS=5000 workaround leaking through, which would validate the
# workaround instead of the product. This suite runs fully hermetic (env -i +
# empty HOME), so unlike the fleet suite it can demand the strict "default".
budget_source="$(printf '%s' "$budget_line" | jq -r '
  .general.hook_timeout_source // empty' 2>/dev/null | head -1)"
if [[ -z "$effective_budget" ]]; then
  report fail latency "default-budget" "could not read general.hook_timeout_ms from 'dcg config --format json'"
elif [[ "$budget_source" != "default" ]]; then
  report fail latency "default-budget" \
    "budget source is '${budget_source}', not 'default' — this suite is hermetic, so an override reaching it means the sandbox is broken and these latency assertions prove nothing"
elif [[ "$effective_budget" -ge 1000 ]]; then
  report pass latency "default-budget=${effective_budget}ms (source=default)"
else
  report fail latency "default-budget" \
    "stock budget is ${effective_budget}ms; #245 proved <1000ms is exceeded by ordinary commands"
fi

# ---------------------------------------------------------------------------
$JSON_OUTPUT || { echo; echo "Passed: $PASS   Failed: $FAIL"; }
log_json "$(jq -nc --arg r "$RUN_ID" --argjson p "$PASS" --argjson f "$FAIL" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{ts:$ts,run_id:$r,event:"summary",suite:"harness_matrix",passed:$p,failed:$f,
    result:(if $f == 0 then "pass" else "fail" end)}')"

if [[ $FAIL -gt 0 ]]; then
  $JSON_OUTPUT || { echo; echo "Failures:"; printf '  %s\n' "${FAILURES[@]}"; }
  echo "harness matrix FAILED ($FAIL failures); sandbox preserved: $SANDBOX" >&2
  exit 1
fi
$JSON_OUTPUT || echo "All harness protocol assertions passed."
exit 0
