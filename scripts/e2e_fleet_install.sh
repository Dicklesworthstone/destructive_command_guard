#!/usr/bin/env bash
# e2e_fleet_install.sh — install dcg on every real platform from the PUBLIC
# release URL using the same tag-pinned installer bytes as `dcg update`, then
# prove the installed binary actually guards commands.
#
# WHY THIS EXISTS
# ---------------
# Unit tests, `cargo test`, and even the local e2e suite all run a binary that
# was built in this working tree. None of them prove that:
#   * the published artifact for a given platform exists and is downloadable,
#   * the installer picks the right target triple for that platform,
#   * checksum/signature verification passes against the published sidecars,
#   * the installed binary runs on that OS (glibc/musl/Rosetta/PE issues), and
#   * the hook protocol still works when invoked the way an agent invokes it.
# Every one of those has broken a release before. This suite is the only gate
# that exercises the real user path on real machines.
#
# SAFETY: installs into a throwaway directory with an isolated HOME and passes
# --no-configure by default, so no agent hook config on any host is touched.
# Hook-configuration idempotency is tested separately inside the sandbox HOME.
#
# Usage:
#   scripts/e2e_fleet_install.sh [--version vX.Y.Z] [--hosts "trj ts1"]
#                                [--local-only] [--no-windows] [--json]
#
#   --version     Release to install (default: latest published; needs gh auth)
#   --hosts       Space-separated Unix SSH hosts (default: trj ts1)
#   --local-only  This machine only; implies --no-windows
#   --no-windows  Skip the native-Windows host (included by default)
#   --json        JSON-line events on stdout instead of the human table
#
# Exit: 0 all reachable hosts passed, 1 any failure, 2 usage/setup error.
set -uo pipefail

VERSION=""
HOSTS_OVERRIDE=""
JSON_OUTPUT=false
INCLUDE_WINDOWS=true
LOCAL_ONLY=false
REPO_RAW="https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard"
REPO_RELEASE="https://github.com/Dicklesworthstone/destructive_command_guard/releases/download"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --hosts) HOSTS_OVERRIDE="${2:-}"; shift 2 ;;
    --json) JSON_OUTPUT=true; shift ;;
    --include-windows) INCLUDE_WINDOWS=true; shift ;;
    --no-windows) INCLUDE_WINDOWS=false; shift ;;
    --local-only) LOCAL_ONLY=true; shift ;;
    --help|-h) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION="$(gh release view -R Dicklesworthstone/destructive_command_guard \
    --json tagName --jq .tagName 2>/dev/null)"
  [[ -z "$VERSION" ]] && { echo "error: --version required (could not query latest)" >&2; exit 2; }
fi
[[ "$VERSION" == v* ]] || VERSION="v$VERSION"

# Unix SSH hosts drawn from the DSR fleet (~/.config/dsr/hosts.yaml).
UNIX_SSH_HOSTS=(trj ts1)
WINDOWS_SSH_HOST="surfacebookje"
[[ -n "$HOSTS_OVERRIDE" ]] && read -r -a UNIX_SSH_HOSTS <<< "$HOSTS_OVERRIDE"
$LOCAL_ONLY && UNIX_SSH_HOSTS=() && INCLUDE_WINDOWS=false

PASS=0; FAIL=0; SKIP=0
declare -a FAILURES=()

emit() {
  $JSON_OUTPUT && printf '%s\n' "$1" || true
}
report() {
  local status="$1" host="$2" case_name="$3" detail="${4:-}"
  case "$status" in
    pass) PASS=$((PASS+1)); $JSON_OUTPUT || printf '  \033[0;32m✓\033[0m %-16s %s\n' "$host" "$case_name" ;;
    skip) SKIP=$((SKIP+1)); $JSON_OUTPUT || printf '  \033[0;33m-\033[0m %-16s %s (%s)\n' "$host" "$case_name" "$detail" ;;
    *)    FAIL=$((FAIL+1)); FAILURES+=("$host/$case_name: $detail")
          $JSON_OUTPUT || printf '  \033[0;31m✗\033[0m %-16s %s\n     %s\n' "$host" "$case_name" "$detail" ;;
  esac
  emit "$(jq -nc --arg h "$host" --arg c "$case_name" --arg s "$status" --arg d "$detail" \
    '{event:"case",host:$h,case:$c,status:$s,detail:$d}' 2>/dev/null || echo '{}')"
}

# ---------------------------------------------------------------------------
# The remote script. Runs on each Unix host: downloads the PUBLIC installer,
# installs the pinned version into a scratch prefix with an isolated HOME,
# then exercises the real hook protocol against the installed binary.
# Prints RESULT: lines the caller parses.
# ---------------------------------------------------------------------------
unix_probe() {
cat <<'PROBE'
set -u
VERSION="$1"; REPO_RAW="$2"; REPO_RELEASE="$3"

# Drop every ambient DCG_* for the WHOLE probe, before anything runs. The hook
# calls below additionally use `env -i`, but the installer cannot: it needs the
# host's real PATH to find curl/tar/xz/minisign. Without this, an operator's
# DCG_HOOK_TIMEOUT_MS=5000 (the #245 workaround) would still reach the
# installer's self-test and any non-`env -i` invocation.
for _dcg_var in $(env | sed -n 's/^\(DCG_[A-Za-z0-9_]*\)=.*/\1/p'); do
  unset "$_dcg_var" 2>/dev/null || true
done
# Disable self-heal for the WHOLE probe, including the installer's self-test.
# dcg repairs a missing/stale hook entry whenever it runs in hook mode; HOME is
# redirected below so a repair would land in the sandbox, but exporting this up
# front means no invocation can ever rewrite a real agent config.
export DCG_SELF_HEAL_HOOK=0
export DCG_HISTORY_DISABLED=1

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dcg-fleet-e2e.XXXXXX")" || exit 2
HOME_SANDBOX="$WORK/home"; DEST="$WORK/bin"
mkdir -p "$HOME_SANDBOX" "$DEST"
cd "$WORK" || exit 2

echo "RESULT:platform:$(uname -s)/$(uname -m)"

# 1. Fetch the exact tag-pinned installer that `dcg update` executes.
if ! curl -fsSL -o "$WORK/install.sh" "$REPO_RAW/$VERSION/install.sh"; then
  echo "RESULT:fetch_installer:FAIL:curl failed"; exit 1
fi
echo "RESULT:fetch_installer:PASS"

# 2. Verify the installer itself before executing it. Archive verification
# cannot protect users from a modified installer that has already started.
if ! curl -fsSL -o "$WORK/install.sh.sha256" \
    "$REPO_RELEASE/$VERSION/install.sh.sha256"; then
  echo "RESULT:installer_checksum_verified:FAIL:install.sh.sha256 unavailable"; exit 1
fi
INSTALLER_EXPECTED="$(awk 'NF { print $1; exit }' "$WORK/install.sh.sha256" | tr -d '\r')"
if [ "${#INSTALLER_EXPECTED}" -ne 64 ]; then
  echo "RESULT:installer_checksum_verified:FAIL:malformed install.sh.sha256"; exit 1
fi
case "$INSTALLER_EXPECTED" in
  *[!0-9a-fA-F]*) echo "RESULT:installer_checksum_verified:FAIL:non-hex install.sh.sha256"; exit 1 ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
  INSTALLER_ACTUAL="$(sha256sum "$WORK/install.sh" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  INSTALLER_ACTUAL="$(shasum -a 256 "$WORK/install.sh" | awk '{print $1}')"
else
  echo "RESULT:installer_checksum_verified:FAIL:no SHA256 verifier"; exit 1
fi
if [ "$(printf '%s' "$INSTALLER_ACTUAL" | tr 'A-F' 'a-f')" != \
     "$(printf '%s' "$INSTALLER_EXPECTED" | tr 'A-F' 'a-f')" ]; then
  echo "RESULT:installer_checksum_verified:FAIL:install.sh digest mismatch"; exit 1
fi
echo "RESULT:installer_checksum_verified:PASS:$INSTALLER_ACTUAL"

# 3. Install the pinned version with the release's long-lived signature as a
#    hard requirement. This is a release gate, so a host without the verifier
#    is missing gate infrastructure rather than evidence that may be skipped.
INSTALL_LOG="$WORK/install.log"
if HOME="$HOME_SANDBOX" XDG_CONFIG_HOME="$HOME_SANDBOX/.config" \
   bash "$WORK/install.sh" --version "$VERSION" --dest "$DEST" \
     --require-minisign --verify --no-configure >"$INSTALL_LOG" 2>&1; then
  echo "RESULT:install:PASS:checksum+minisign"
else
  echo "RESULT:install:FAIL:$(tail -3 "$INSTALL_LOG" | tr '\n' ' ')"
  echo "RESULT:minisign_verified:FAIL:strict signed install did not complete"
  exit 1
fi

# 4. Prove archive verification actually happened (not silently skipped).
grep -qi "checksum" "$INSTALL_LOG" && echo "RESULT:checksum_verified:PASS" \
  || echo "RESULT:checksum_verified:FAIL:no checksum evidence in installer output"
grep -qi "Signature verified (minisign key " "$INSTALL_LOG" \
  && echo "RESULT:minisign_verified:PASS" \
  || echo "RESULT:minisign_verified:FAIL:no minisign key verification evidence"

BIN="$DEST/dcg"
[ -x "$BIN" ] || { echo "RESULT:binary_present:FAIL:not executable at $BIN"; exit 1; }
echo "RESULT:binary_present:PASS"

# 5. The installed binary must run on THIS os/arch, report the pinned version,
#    and prove it was built from exactly that clean release tag. A semver-only
#    check would have accepted the v0.13.0 macOS `v0.13.0-dirty` artifacts.
VERSION_OUTPUT="$("$BIN" --version 2>&1 | tr -d '\r')"
GOT_VERSION="$(printf '%s\n' "$VERSION_OUTPUT" | head -1)"
case "$GOT_VERSION" in
  *"${VERSION#v}"*) echo "RESULT:version_match:PASS:$GOT_VERSION" ;;
  *) echo "RESULT:version_match:FAIL:want ${VERSION#v} got '$GOT_VERSION'" ;;
esac
EMBEDDED_DESCRIBE="$(printf '%s\n' "$VERSION_OUTPUT" \
  | sed -nE 's/.*Commit:[[:space:]]+([^[:space:]]+).*/\1/p' \
  | head -1)"
if [ "$EMBEDDED_DESCRIBE" = "$VERSION" ]; then
  echo "RESULT:provenance_match:PASS:$EMBEDDED_DESCRIBE"
else
  echo "RESULT:provenance_match:FAIL:want $VERSION got '${EMBEDDED_DESCRIBE:-<missing>}'"
fi

# 5. Real hook protocol against the installed artifact.
#
# `env -i` is MANDATORY here, not hygiene. Operators bitten by #245 carry
# DCG_HOOK_TIMEOUT_MS=5000 in their agent env — inheriting it would run the
# #245 guard below against the workaround instead of the shipped default and
# make this suite pass on precisely the machines it needs to protect. Scrub
# every ambient DCG_* and pin HOME so no user config leaks in either.
SAFE_PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
dcg_env() {
  env -i PATH="$SAFE_PATH" HOME="$HOME_SANDBOX" USERPROFILE="$HOME_SANDBOX" \
    XDG_CONFIG_HOME="$HOME_SANDBOX/.config" TMPDIR="${TMPDIR:-/tmp}" \
    DCG_SELF_HEAL_HOOK=0 DCG_HISTORY_DISABLED=1 "$@"
}
run_hook() {
  printf '%s' "$1" | dcg_env "$BIN" 2>/dev/null
}

# Prove the scrub worked: the binary must report the SHIPPED default budget.
# If this reads back an operator's override, every latency assertion below is
# meaningless.
BUDGET_JSON="$(dcg_env "$BIN" config --format json 2>/dev/null)"
EFFECTIVE_BUDGET="$(printf '%s' "$BUDGET_JSON" \
  | grep -o '"hook_timeout_ms"[[:space:]]*:[[:space:]]*[0-9]*' \
  | grep -o '[0-9]*$' | head -1)"
# `hook_timeout_source` is the decisive signal, and the distinction matters:
#
#   default                            -> the shipped budget. Ideal.
#   <preset> preset                    -> a PRODUCT default for a documented
#                                         posture (careful_company = 3000ms).
#                                         Legitimate; the guard still holds.
#   configured                         -> someone set hook_timeout_ms or
#                                         DCG_HOOK_TIMEOUT_MS. REJECT: that is
#                                         the #245 workaround, and measuring
#                                         against it validates the workaround
#                                         instead of the product.
#
# Note native Windows resolves the user config through the Win32 known-folder
# API, so USERPROFILE/HOME cannot redirect it — a host may legitimately carry a
# preset. Only an explicit timeout override invalidates these assertions.
BUDGET_SOURCE="$(printf '%s' "$BUDGET_JSON" \
  | grep -o '"hook_timeout_source"[[:space:]]*:[[:space:]]*"[^"]*"' \
  | sed 's/.*"\([^"]*\)"$/\1/' | head -1)"
if [ -z "$EFFECTIVE_BUDGET" ]; then
  echo "RESULT:effective_budget:FAIL:could not read general.hook_timeout_ms"
elif [ "$BUDGET_SOURCE" = "configured" ]; then
  echo "RESULT:effective_budget:FAIL:budget is explicitly configured (${EFFECTIVE_BUDGET}ms) — an operator override reached this run, so the latency assertions would validate the workaround, not the product"
# 1000 here is a deliberate FLOOR, not a copy of the current default: #245
# proved ordinary commands exceed anything below it. A future release may
# raise the default (that still passes); it must never drop under this.
elif [ "$EFFECTIVE_BUDGET" -lt 1000 ]; then
  echo "RESULT:effective_budget:FAIL:${EFFECTIVE_BUDGET}ms — below the 1000ms floor that #245 established (ordinary commands exceed it)"
else
  echo "RESULT:effective_budget:PASS:${EFFECTIVE_BUDGET}ms (source=${BUDGET_SOURCE})"
fi
DENY_PAYLOAD='{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}'
ALLOW_PAYLOAD='{"tool_name":"Bash","tool_input":{"command":"git status"}}'

OUT="$(run_hook "$DENY_PAYLOAD")"
case "$OUT" in
  *'"permissionDecision":"deny"'*) echo "RESULT:hook_deny:PASS" ;;
  "") echo "RESULT:hook_deny:FAIL:empty stdout — destructive command would RUN" ;;
  *) echo "RESULT:hook_deny:FAIL:unexpected: $(printf '%s' "$OUT" | head -c 120)" ;;
esac

OUT="$(run_hook "$ALLOW_PAYLOAD")"
[ -z "$OUT" ] && echo "RESULT:hook_allow:PASS" \
  || echo "RESULT:hook_allow:FAIL:safe command produced output: $(printf '%s' "$OUT" | head -c 120)"

# 6. #245 guard on real hardware: ordinary commands must reach a verdict with
#    the SHIPPED default budget (no DCG_HOOK_TIMEOUT_MS anywhere).
INDET=0
for CMD in 'echo hi 2>/dev/null' 'cp report.txt backup.txt' 'rm ./scratch.txt' '[ -f x ]'; do
  P="$(printf '{"tool_name":"Bash","tool_input":{"command":"%s"}}' \
        "$(printf '%s' "$CMD" | sed 's/\\/\\\\/g; s/"/\\"/g')")"
  O="$(run_hook "$P")"
  case "$O" in
    *"could not complete safety evaluation"*) INDET=$((INDET+1)); echo "RESULT:latency_detail:$CMD:INDETERMINATE" ;;
    *'"permissionDecision":"ask"'*) INDET=$((INDET+1)); echo "RESULT:latency_detail:$CMD:ASK" ;;
  esac
done
[ "$INDET" -eq 0 ] && echo "RESULT:no_indeterminate_verdicts:PASS" \
  || echo "RESULT:no_indeterminate_verdicts:FAIL:$INDET command(s) blew the stock deadline on this host"

# 7. Latency on real hardware. Raw wall-clock includes process-spawn overhead
#    that sits OUTSIDE dcg's deadline (which starts after stdin is read), so
#    isolate dcg's own cost by differencing against a DCG_BYPASS run that pays
#    identical spawn cost with no evaluation. That delta must fit the budget.
# `date +%s%N` is a GNU extension; a BSD date that lacks it returns a literal
# trailing "N", which turns the arithmetic below into garbage. Detect support
# once and fall back to python3 so timing is either correct or explicitly
# skipped — never silently wrong.
NOW_NS_CMD=""
if _probe="$(date +%s%N 2>/dev/null)" && [ "${_probe#*N}" = "$_probe" ] \
   && [ ${#_probe} -ge 16 ]; then
  NOW_NS_CMD="date"
elif command -v python3 >/dev/null 2>&1; then
  NOW_NS_CMD="python3"
fi
now_ns() {
  case "$NOW_NS_CMD" in
    date) date +%s%N ;;
    python3) python3 -c 'import time; print(time.monotonic_ns())' ;;
    *) echo "" ;;
  esac
}

# Returns the FLOOR (minimum) of N samples, not the median.
#
# These hosts are shared build machines. A median on a box at load average 115
# measures the box's contention, not dcg's per-invocation cost, and produces
# failures that have nothing to do with the code under test. The minimum is
# "what dcg costs when it actually gets the CPU" — the quantity a cost
# regression would move. If even the best of N exceeds half the budget, that
# is a real problem rather than a noisy neighbour.
floor_ms() {  # $1 = extra env ("" or DCG_BYPASS=1)
  [ -z "$NOW_NS_CMD" ] && { echo ""; return; }
  _samples=""
  for _ in 1 2 3 4 5; do
    _s=$(now_ns) || { echo ""; return; }
    [ -z "$_s" ] && { echo ""; return; }
    if [ -n "$1" ]; then
      printf '%s' "$PERF_PAYLOAD" | env -i PATH="$SAFE_PATH" HOME="$HOME_SANDBOX" \
        USERPROFILE="$HOME_SANDBOX" XDG_CONFIG_HOME="$HOME_SANDBOX/.config" \
        TMPDIR="${TMPDIR:-/tmp}" DCG_SELF_HEAL_HOOK=0 \
        DCG_HISTORY_DISABLED=1 "$1" "$BIN" >/dev/null 2>&1
    else
      run_hook "$PERF_PAYLOAD" >/dev/null
    fi
    _e=$(now_ns)
    _samples="$_samples $(( (_e - _s) / 1000000 ))"
  done
  printf '%s' "$_samples" | tr ' ' '\n' | grep -v '^$' | sort -n | sed -n '1p'
}
PERF_PAYLOAD='{"tool_name":"Bash","tool_input":{"command":"cp report.txt backup.txt"}}'
SPAWN_MS="$(floor_ms DCG_BYPASS=1)"
TOTAL_MS="$(floor_ms "")"
if [ -n "$SPAWN_MS" ] && [ -n "$TOTAL_MS" ]; then
  EVAL_MS=$((TOTAL_MS - SPAWN_MS)); [ "$EVAL_MS" -lt 0 ] && EVAL_MS=0
  echo "RESULT:latency_ms:INFO:floor_total=${TOTAL_MS} floor_spawn=${SPAWN_MS} dcg_eval=${EVAL_MS}"
  # These are shared, uncontrolled machines: a busy neighbour can dominate the
  # sample even at the floor, so a PERCENTAGE gate here would be flaky and
  # would say nothing about the code. The strict "<50% of budget" gate lives in
  # CI on a dedicated runner. What matters on a real host is the user-visible
  # outcome: does evaluation still fit inside the budget at all? If it does
  # not, users on this machine WILL get fail-closed review prompts (#245).
  # `no_indeterminate_verdicts` above independently proves the functional side.
  # Compare against the budget THIS host actually resolved, not a literal.
  # A machine running the careful_company preset has a 3000ms budget, so a
  # hard-coded 1000 would fail it for a latency its users never feel — and
  # would silently stop matching the product if the default ever moved.
  _budget="${EFFECTIVE_BUDGET:-1000}"
  if [ "$EVAL_MS" -lt "$_budget" ]; then
    echo "RESULT:latency_under_budget:PASS:dcg_eval=${EVAL_MS}ms floor (budget ${_budget}ms; strict 50% gate runs in CI)"
  else
    echo "RESULT:latency_under_budget:FAIL:dcg evaluation floor is ${EVAL_MS}ms, at or over this host's entire ${_budget}ms budget — users here hit indeterminate verdicts (#245)"
  fi
else
  # Emit explicitly rather than staying silent: an absent case would trip the
  # runner's coverage gate with a misleading "probe truncated" message.
  echo "RESULT:latency_under_budget:SKIP:no nanosecond clock available on this host"
fi

# 8. Hook configuration is idempotent, in the sandbox HOME (never the real one).
#    Running install twice must leave exactly one dcg entry and valid JSON —
#    a duplicate or corrupted settings file breaks the user's whole agent.
sandboxed() { dcg_env "$@"; }
count_dcg_entries() {
  python3 - "$1" "$2" <<'PY'
import json, sys
path, kind = sys.argv[1], sys.argv[2]
try:
    doc = json.load(open(path))
except Exception:
    print("INVALID"); raise SystemExit(0)
n = 0
if kind == "claude":
    groups = doc.get("hooks", {}).get("PreToolUse", [])
    for group in groups:
        for hook in group.get("hooks", []):
            if "dcg" in str(hook.get("command", "")):
                n += 1
else:  # grok / agy style: any nested command string mentioning dcg
    def walk(node):
        global n
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("command", "cmd") and "dcg" in str(v):
                    n += 1
                else:
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(doc)
print(n)
PY
}

if command -v python3 >/dev/null 2>&1; then
  # Claude Code (default target), Grok, and Antigravity all in the sandbox.
  sandboxed "$BIN" install  >/dev/null 2>&1
  sandboxed "$BIN" install  >/dev/null 2>&1
  sandboxed "$BIN" install --grok >/dev/null 2>&1
  sandboxed "$BIN" install --grok >/dev/null 2>&1
  sandboxed "$BIN" install --agy  >/dev/null 2>&1
  sandboxed "$BIN" install --agy  >/dev/null 2>&1

  check_hook_file() {
    label="$1"; file="$2"; kind="$3"
    if [ ! -f "$file" ]; then
      echo "RESULT:hook_install_$label:FAIL:install wrote no $file"
      return
    fi
    c="$(count_dcg_entries "$file" "$kind")"
    case "$c" in
      1) echo "RESULT:hook_install_$label:PASS" ;;
      INVALID) echo "RESULT:hook_install_$label:FAIL:$file is not valid JSON after install" ;;
      *) echo "RESULT:hook_install_$label:FAIL:$c dcg entries after two installs (want 1)" ;;
    esac
  }
  check_hook_file claude "$HOME_SANDBOX/.claude/settings.json" claude
  check_hook_file grok   "$HOME_SANDBOX/.grok/hooks/dcg.json"  other
  check_hook_file agy    "$HOME_SANDBOX/.gemini/config/hooks.json" other

  # The hook command must be an ABSOLUTE path (v0.7.7): a bare `dcg` fails
  # open under a non-interactive agent shell whose PATH lacks ~/.local/bin.
  if [ -f "$HOME_SANDBOX/.claude/settings.json" ]; then
    if python3 - "$HOME_SANDBOX/.claude/settings.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
cmds = [h.get("command", "")
        for g in doc.get("hooks", {}).get("PreToolUse", [])
        for h in g.get("hooks", [])
        if "dcg" in str(h.get("command", ""))]
raise SystemExit(0 if cmds and all(c.strip().startswith(("/", "&", "'", '"')) for c in cmds) else 1)
PY
    then echo "RESULT:hook_absolute_path:PASS"
    else echo "RESULT:hook_absolute_path:FAIL:hook registered without an absolute dcg path (fails open on PATH-less shells)"
    fi
  fi
else
  echo "RESULT:hook_install_claude:SKIP:python3 unavailable"
fi

echo "RESULT:workdir:INFO:$WORK"
echo "RESULT:probe_complete:PASS"
PROBE
}

# The Windows probe. Fully quoted so bash performs NO substitution — the
# caller prepends `$Version` / `$RepoRaw` assignments. Every step is wrapped so
# a failure still emits a RESULT line instead of silently truncating output.
windows_probe() {
cat <<'PSEOF'
$ErrorActionPreference = 'Continue'
function Emit([string]$name, [string]$status, [string]$detail = '') {
  if ($detail) { Write-Output "RESULT:${name}:${status}:${detail}" }
  else { Write-Output "RESULT:${name}:${status}" }
}
Emit 'platform' 'INFO' "Windows/$env:PROCESSOR_ARCHITECTURE"
# Scrub ambient DCG_* FIRST, before the installer runs. An operator override
# (notably the DCG_HOOK_TIMEOUT_MS=5000 workaround from #245) must not reach
# the installer's self-test or any assertion below.
Get-ChildItem Env: | Where-Object { $_.Name -like 'DCG_*' } | ForEach-Object {
  Remove-Item "Env:$($_.Name)" -ErrorAction SilentlyContinue
}
# Disable self-heal BEFORE the installer runs, not after. dcg repairs a missing
# or stale hook entry whenever it is invoked in hook mode, and native Windows
# resolves the settings path through the Win32 known-folder API — USERPROFILE
# cannot redirect it. Without this, the installer's self-test could rewrite the
# HOST'S REAL ~/.claude/settings.json, breaking this suite's guarantee that it
# never touches a machine's agent configuration.
$env:DCG_SELF_HEAL_HOOK = '0'
$env:DCG_HISTORY_DISABLED = '1'
$work = Join-Path $env:TEMP ("dcg-fleet-e2e-" + [System.Guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$dest = Join-Path $work 'bin'
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$homeSandbox = Join-Path $work 'home'
New-Item -ItemType Directory -Force -Path $homeSandbox | Out-Null

# Use the same tag-pinned installer bytes as `dcg update`, but retain the
# documented scriptblock invocation after the bytes have been verified.
$installerPath = Join-Path $work 'install.ps1'
$installerChecksumPath = Join-Path $work 'install.ps1.sha256'
try {
  Invoke-WebRequest -UseBasicParsing -Uri "$RepoRaw/$Version/install.ps1" -OutFile $installerPath
  Emit 'fetch_installer' 'PASS'
} catch {
  Emit 'fetch_installer' 'FAIL' $_.Exception.Message
  Emit 'probe_complete' 'PASS'
  exit 0
}

try {
  Invoke-WebRequest -UseBasicParsing -Uri "$RepoRelease/$Version/install.ps1.sha256" -OutFile $installerChecksumPath
  $expectedInstallerSha = ((Get-Content -LiteralPath $installerChecksumPath -Raw).Trim() -split '\s+')[0]
  if ($expectedInstallerSha -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'install.ps1.sha256 is malformed'
  }
  $actualInstallerSha = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualInstallerSha -cne $expectedInstallerSha.ToLowerInvariant()) {
    throw 'install.ps1 digest mismatch'
  }
  Emit 'installer_checksum_verified' 'PASS' $actualInstallerSha
  $installerSource = Get-Content -LiteralPath $installerPath -Raw
} catch {
  Emit 'installer_checksum_verified' 'FAIL' $_.Exception.Message
  Emit 'probe_complete' 'PASS'
  exit 0
}

$log = Join-Path $work 'install.log'
try {
  & ([scriptblock]::Create($installerSource)) -Version $Version -Dest $dest `
      -RequireMinisign -Verify -NoConfigure *> $log
  Emit 'install' 'PASS'
} catch {
  $tail = ''
  if (Test-Path $log) { $tail = (Get-Content $log -Tail 3 -ErrorAction SilentlyContinue) -join ' ' }
  Emit 'install' 'FAIL' "$($_.Exception.Message) $tail"
}

$logText = ''
if (Test-Path $log) { $logText = Get-Content $log -Raw -ErrorAction SilentlyContinue }
if ($logText -match '(?i)checksum') { Emit 'checksum_verified' 'PASS' } else { Emit 'checksum_verified' 'FAIL' 'no checksum evidence in installer output' }
if ($logText -match '(?i)Signature verified \(minisign key ') { Emit 'minisign_verified' 'PASS' } else { Emit 'minisign_verified' 'FAIL' 'strict minisign key verification did not complete' }

$bin = Join-Path $dest 'dcg.exe'
if (Test-Path $bin) {
  Emit 'binary_present' 'PASS'
} else {
  Emit 'binary_present' 'FAIL' "missing dcg.exe in $dest"
  Emit 'probe_complete' 'PASS'
  exit 0
}

$wanted = $Version.TrimStart('v')
$versionOutput = (& $bin --version 2>&1 | Out-String)
$got = ($versionOutput -split "`r?`n" | Select-Object -First 1) -join ''
if ($got -like "*$wanted*") { Emit 'version_match' 'PASS' $got } else { Emit 'version_match' 'FAIL' "want $wanted got '$got'" }
$describeMatch = [regex]::Match($versionOutput, 'Commit:\s+(\S+)')
$embeddedDescribe = if ($describeMatch.Success) { $describeMatch.Groups[1].Value } else { '' }
if ($embeddedDescribe -ceq $Version) { Emit 'provenance_match' 'PASS' $embeddedDescribe } else { Emit 'provenance_match' 'FAIL' "want $Version got '$embeddedDescribe'" }

# DCG_SELF_HEAL_HOOK / DCG_HISTORY_DISABLED are already set at the top of this
# probe, before the installer ran.
#
# Native Windows resolves the user config from %APPDATA%\dcg (per docs/windows.md),
# NOT from USERPROFILE — redirecting only the latter leaves the host's real
# config (e.g. an enabled careful_company_running_windows preset, which raises
# the budget to 3000ms) in play and silently invalidates the latency guards.
$env:USERPROFILE = $homeSandbox
$env:HOME = $homeSandbox
$env:APPDATA = Join-Path $homeSandbox 'AppData\Roaming'
$env:LOCALAPPDATA = Join-Path $homeSandbox 'AppData\Local'
$env:XDG_CONFIG_HOME = Join-Path $homeSandbox '.config'
New-Item -ItemType Directory -Force -Path $env:APPDATA, $env:LOCALAPPDATA | Out-Null
function HookOut([string]$payload) {
  return ($payload | & $bin 2>$null | Out-String)
}

# Prove the scrub worked: the binary must report the shipped default budget.
$cfg = (& $bin config --format json 2>$null | Out-String)
$budget = $null
$source = $null
if ($cfg -match '"hook_timeout_ms"\s*:\s*(\d+)') { $budget = [int]$Matches[1] }
if ($cfg -match '"hook_timeout_source"\s*:\s*"([^"]*)"') { $source = $Matches[1] }
# See the Unix probe for the source semantics: a preset is a product default
# and is acceptable; an explicit `configured` override is not. Windows resolves
# the user config via the Win32 known-folder API, so it cannot be redirected by
# USERPROFILE/HOME and a host may legitimately carry a preset.
if ($null -eq $budget) {
  Emit 'effective_budget' 'FAIL' 'could not read general.hook_timeout_ms'
} elseif ($source -eq 'configured') {
  Emit 'effective_budget' 'FAIL' "budget is explicitly configured (${budget}ms) — an operator override reached this run"
} elseif ($budget -lt 1000) {
  Emit 'effective_budget' 'FAIL' "${budget}ms — below the 1000ms shipped default"
} else {
  Emit 'effective_budget' 'PASS' "${budget}ms (source=$source)"
}
$deny = '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}'
$allow = '{"tool_name":"Bash","tool_input":{"command":"git status"}}'
$out = HookOut $deny
if ($out -match '"permissionDecision"\s*:\s*"deny"') { Emit 'hook_deny' 'PASS' } else { Emit 'hook_deny' 'FAIL' 'destructive command was NOT denied' }
$out = (HookOut $allow).Trim()
if ([string]::IsNullOrEmpty($out)) { Emit 'hook_allow' 'PASS' } else { Emit 'hook_allow' 'FAIL' 'safe command produced output' }

# Native-Windows default packs must be ON: these are catastrophic there.
$psPayload = '{"tool_name":"PowerShell","tool_input":{"command":"Remove-Item -Recurse -Force C:\\data"}}'
$out = HookOut $psPayload
if ($out -match 'deny|block') { Emit 'windows_default_packs' 'PASS' } else { Emit 'windows_default_packs' 'FAIL' 'windows.filesystem is not default-on for Remove-Item -Recurse' }
$cmdPayload = '{"tool_name":"Bash","tool_input":{"command":"vssadmin delete shadows /all /quiet"}}'
$out = HookOut $cmdPayload
if ($out -match 'deny|block') { Emit 'windows_shadow_copy_guard' 'PASS' } else { Emit 'windows_shadow_copy_guard' 'FAIL' 'windows.system not default-on for vssadmin delete shadows' }

# #245 guard on native Windows with the SHIPPED default budget.
$indet = 0
foreach ($c in @('echo hi 2>NUL', 'cp report.txt backup.txt', 'rm ./scratch.txt')) {
  $escaped = $c.Replace('\', '\\').Replace('"', '\"')
  $p = '{"tool_name":"Bash","tool_input":{"command":"' + $escaped + '"}}'
  $o = HookOut $p
  if ($o -match 'could not complete safety evaluation' -or $o -match '"ask"') { $indet++ }
}
if ($indet -eq 0) { Emit 'no_indeterminate_verdicts' 'PASS' } else { Emit 'no_indeterminate_verdicts' 'FAIL' "$indet command(s) blew the stock deadline" }

# Latency on real Windows hardware.
#
# Raw wall-clock here includes PowerShell's process-spawn and pipeline
# overhead, which is OUTSIDE dcg's evaluation deadline (the deadline starts
# after stdin is read). Comparing raw wall-clock to the budget would produce a
# false alarm on a slow shell. Instead measure dcg's OWN cost by differencing
# against a DCG_BYPASS run, which pays identical spawn overhead but does no
# evaluation. That delta is what must fit the budget.
# Floor (minimum), not median — see the Unix probe: on a shared or busy host a
# median measures contention rather than dcg's per-invocation cost.
function FloorMs([scriptblock]$action, [int]$iterations = 5) {
  $samples = @()
  foreach ($i in 1..$iterations) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $action | Out-Null
    $sw.Stop()
    $samples += $sw.ElapsedMilliseconds
  }
  return ($samples | Measure-Object -Minimum).Minimum
}
$payload = '{"tool_name":"Bash","tool_input":{"command":"cp report.txt backup.txt"}}'
$env:DCG_BYPASS = '1'
$spawnMs = FloorMs { HookOut $payload }
Remove-Item Env:\DCG_BYPASS -ErrorAction SilentlyContinue
$totalMs = FloorMs { HookOut $payload }
$evalMs = $totalMs - $spawnMs
if ($evalMs -lt 0) { $evalMs = 0 }
Emit 'latency_ms' 'INFO' "floor_total=$totalMs floor_spawn=$spawnMs dcg_eval=$evalMs"
# See the Unix probe: percentage gates belong on the dedicated CI runner, not
# on shared hardware. Here we assert the user-visible outcome instead.
# Compare against the budget THIS host resolved (see the Unix probe): the
# careful_company preset legitimately raises it to 3000ms.
$effBudget = if ($null -ne $budget) { $budget } else { 1000 }
if ($evalMs -lt $effBudget) { Emit 'latency_under_budget' 'PASS' "dcg_eval=${evalMs}ms floor (budget ${effBudget}ms; strict 50% gate runs in CI)" } else { Emit 'latency_under_budget' 'FAIL' "dcg evaluation floor is ${evalMs}ms, at or over this host's entire ${effBudget}ms budget — users here hit indeterminate verdicts (#245)" }

Emit 'workdir' 'INFO' $work
Emit 'probe_complete' 'PASS'
PSEOF
}

# ---------------------------------------------------------------------------
# Every probe must announce probe_complete. Without this, a probe that dies
# halfway through (bad quoting, crashed shell) looks like a clean pass.
EXPECTED_CASES=(fetch_installer installer_checksum_verified install checksum_verified minisign_verified binary_present
                version_match provenance_match effective_budget hook_deny hook_allow
                no_indeterminate_verdicts latency_under_budget probe_complete)

parse_results() {
  local host="$1" output="$2"
  local saw_any=false
  # Windows probes return CRLF; a trailing \r would make "PASS\r" != "PASS"
  # and silently downgrade every assertion to an informational line.
  output="${output//$'\r'/}"
  while IFS= read -r line; do
    case "$line" in
      RESULT:*) ;;
      *) continue ;;
    esac
    saw_any=true
    local rest="${line#RESULT:}"
    local name="${rest%%:*}"; rest="${rest#*:}"
    local status="${rest%%:*}"; local detail="${rest#*:}"
    [[ "$detail" == "$status" ]] && detail=""
    case "$status" in
      PASS) report pass "$host" "$name" "$detail" ;;
      FAIL) report fail "$host" "$name" "$detail" ;;
      SKIP) report skip "$host" "$name" "$detail" ;;
      INFO) $JSON_OUTPUT || printf '  \033[0;36mi\033[0m %-16s %s: %s\n' "$host" "$name" "$detail"
            emit "$(jq -nc --arg h "$host" --arg c "$name" --arg d "$detail" \
              '{event:"info",host:$h,case:$c,detail:$d}' 2>/dev/null || echo '{}')" ;;
      *) # platform line and other bare values
         $JSON_OUTPUT || printf '  \033[0;36mi\033[0m %-16s %s: %s\n' "$host" "$name" "$status$detail" ;;
    esac
  done <<< "$output"
  $saw_any || report fail "$host" "probe" "no RESULT lines returned (probe did not run)"

  # Completeness gate: a truncated probe must never read as success.
  local missing=()
  for expected in "${EXPECTED_CASES[@]}"; do
    grep -q "^RESULT:${expected}:" <<< "$output" || missing+=("$expected")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    report fail "$host" "probe_coverage" \
      "probe never reported: ${missing[*]} (output truncated — treat as failure, not success)"
  fi
}

$JSON_OUTPUT || echo "dcg fleet installer e2e — version $VERSION"
$JSON_OUTPUT || echo

# --- Local host (this machine) ---------------------------------------------
$JSON_OUTPUT || echo "local ($(uname -s)/$(uname -m))"
local_out="$(unix_probe | bash -s -- "$VERSION" "$REPO_RAW" "$REPO_RELEASE" 2>&1)"
parse_results "local" "$local_out"

# --- Remote Unix hosts ------------------------------------------------------
for host in "${UNIX_SSH_HOSTS[@]}"; do
  $JSON_OUTPUT || { echo; echo "$host"; }
  if ! ssh -o ConnectTimeout=8 -o BatchMode=yes "$host" 'echo ok' >/dev/null 2>&1; then
    report skip "$host" "reachability" "ssh unreachable"
    continue
  fi
  remote_out="$(unix_probe | ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" \
    "bash -s -- '$VERSION' '$REPO_RAW' '$REPO_RELEASE'" 2>&1)"
  parse_results "$host" "$remote_out"
done

# --- Windows host (native PowerShell installer) -----------------------------
if $INCLUDE_WINDOWS; then
  $JSON_OUTPUT || { echo; echo "$WINDOWS_SSH_HOST (windows)"; }
  if ! ssh -o ConnectTimeout=8 -o BatchMode=yes "$WINDOWS_SSH_HOST" 'echo ok' >/dev/null 2>&1; then
    report skip "$WINDOWS_SSH_HOST" "reachability" "ssh unreachable"
  else
    # Inject parameters as PowerShell variables, then the fully-quoted probe.
    win_out="$( { printf "\$Version = '%s'\n\$RepoRaw = '%s'\n\$RepoRelease = '%s'\n" \
                    "$VERSION" "$REPO_RAW" "$REPO_RELEASE"
                  windows_probe; } \
      | ssh -o ConnectTimeout=10 -o BatchMode=yes "$WINDOWS_SSH_HOST" \
          "powershell -NoProfile -NonInteractive -Command -" 2>&1 )"
    parse_results "$WINDOWS_SSH_HOST" "$win_out"
  fi
fi

$JSON_OUTPUT || { echo; echo "Passed: $PASS   Failed: $FAIL   Skipped: $SKIP"; }
emit "$(jq -nc --argjson p "$PASS" --argjson f "$FAIL" --argjson s "$SKIP" \
  '{event:"summary",passed:$p,failed:$f,skipped:$s}' 2>/dev/null || echo '{}')"

if [[ $FAIL -gt 0 ]]; then
  $JSON_OUTPUT || { echo; echo "Failures:"; printf '  %s\n' "${FAILURES[@]}"; }
  exit 1
fi
$JSON_OUTPUT || echo "Fleet installer e2e passed on every reachable host."
exit 0
