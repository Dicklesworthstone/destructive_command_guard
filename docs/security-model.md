# Security Model: Interactive Mode

This document defines the threat model and security safeguards for dcg's interactive mode, which allows users to allowlist blocked commands through terminal interaction.

## Executive Summary

Interactive mode introduces a security-critical attack surface: if an AI agent can programmatically respond to interactive prompts, dcg's protection becomes ineffective. This document specifies a **dual-factor verification system** combining random verification codes with timing constraints to ensure only human users can bypass blocks.

---

## Threat Model

### Primary Threat: AI Agent Bypass

**Attack scenario:**
1. AI coding agent (Claude, GPT, Codex, etc.) issues a destructive command
2. dcg blocks the command and presents an interactive prompt
3. A malicious prompt injection causes the agent to respond automatically
4. The agent sends the required keystrokes to bypass the block
5. dcg's protection is defeated

**Why this matters:**
- dcg exists specifically to protect users from AI agent mistakes
- If agents can bypass dcg, the tool provides no security value
- Prompt injection attacks are a known vector for manipulating AI agents
- The attack requires no special privileges—just stdin/stdout access

### Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Malicious prompt injection | Control agent responses | Cause damage, exfiltrate data |
| Compromised context | Inject instructions via files | Bypass safety controls |
| Adversarial user | Craft prompts to bypass dcg | Intentional destructive actions |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    User's Terminal                          │
│  ┌─────────────┐       ┌─────────────┐       ┌───────────┐ │
│  │   AI Agent  │──────▶│     dcg     │──────▶│   Shell   │ │
│  │  (untrusted)│       │  (trusted)  │       │ (trusted) │ │
│  └─────────────┘       └─────────────┘       └───────────┘ │
│         │                    │                              │
│         ▼                    ▼                              │
│    stdin/stdout         Interactive                         │
│    (controllable)       prompt (target)                     │
└─────────────────────────────────────────────────────────────┘
```

The critical boundary is between dcg's interactive prompt and the AI agent's ability to send input. Any verification mechanism must ensure that only a human can successfully respond.

---

## Safeguard Analysis

### Option 1: Random Verification Code

```
⚠️  Command blocked: rm -rf ./src

To allowlist this command, type the verification code: 7x3k
>
```

**How it works:**
- Generate a random alphanumeric code each time
- User must type the exact code to proceed
- Code changes on each block event

**Security analysis:**

| Factor | Assessment |
|--------|------------|
| Brute force resistance | 4 chars (a-z, 0-9) = 1,679,616 combinations |
| Replay resistance | Code changes each time |
| OCR resistance | Low—advanced agents could theoretically OCR |
| Automation resistance | High—cannot pre-script the response |

**Strengths:**
- Simple to implement and understand
- High entropy prevents guessing
- Each attempt requires a new code

**Weaknesses:**
- A sufficiently advanced agent with vision capabilities could read the code
- Does not prevent automated timing attacks

**Verdict:** Strong but not sufficient alone.

### Option 2: Timeout Requirement

```
⚠️  Command blocked: rm -rf ./src

Press 'a' within 3 seconds to allowlist...
[3] [2] [1] - Timeout, command remains blocked
```

**How it works:**
- Short window for response (3-5 seconds)
- Countdown displayed to user
- Must respond within window

**Security analysis:**

| Factor | Assessment |
|--------|------------|
| Human reaction time | ~200-500ms typical, easily within window |
| Agent timing | Can potentially time responses programmatically |
| Automation resistance | Medium—timing can be scripted |

**Strengths:**
- Adds temporal constraint
- Humans can easily respond in time
- Prevents slow automated analysis

**Weaknesses:**
- Agents can potentially time their responses
- Does not prevent fast automated responses

**Verdict:** Useful as a secondary factor but not secure alone.

### Option 3: Full Command Retype

```
⚠️  Command blocked: rm -rf ./src

To allowlist, retype the full command:
> rm -rf ./src
```

**How it works:**
- User must retype the exact blocked command
- Character-by-character verification
- Forces acknowledgment of what will execute

**Security analysis:**

| Factor | Assessment |
|--------|------------|
| Automation resistance | Very high—agent would need to echo dangerous command |
| User experience | Poor for long commands |
| Error potential | High—typos require retry |

**Strengths:**
- Forces explicit acknowledgment
- Very difficult for agents to automate safely
- Makes users think about what they're allowing

**Weaknesses:**
- Tedious for complex commands
- May frustrate legitimate users
- Typo-prone

**Verdict:** Highest security but poor UX. Consider as optional "paranoid mode."

### Option 4: Math/CAPTCHA Challenge

```
⚠️  Command blocked: rm -rf ./src

What is 7 + 3?
> 10
```

**Security analysis:**

| Factor | Assessment |
|--------|------------|
| LLM resistance | None—trivial for any LLM to solve |
| Human UX | Good |
| Bot resistance | Traditional bots blocked, LLMs not |

**Verdict:** Ineffective against AI agents. Do not use.

### Option 5: Semantic Verification

```
⚠️  Command blocked: rm -rf ./src

Explain what this command does to confirm you understand:
> [free-form response analyzed for understanding]
```

**Security analysis:**
- Requires NLP to evaluate responses
- LLMs excel at generating plausible explanations
- Adds significant complexity

**Verdict:** Ineffective and overly complex. Do not use.

---

## Recommended Design: Dual-Factor Verification

Based on the analysis above, the recommended approach combines **random verification codes** with **timeout constraints**:

### Mechanism

```
╔══════════════════════════════════════════════════════════════════╗
║  ⚠️  BLOCKED: rm -rf ./src                                        ║
║                                                                  ║
║  Reason: Recursive forced deletion                               ║
║  Rule: core.filesystem:rm-rf-general                             ║
║                                                                  ║
║  To allowlist, type this code within 5 seconds: 7x3k            ║
║  [5] ████████████████████████████████████████                   ║
║                                                                  ║
║  > _                                                             ║
╚══════════════════════════════════════════════════════════════════╝
```

### Security Properties

1. **Randomness:** Code is cryptographically random, unpredictable
2. **Timing:** Response must occur within timeout window
3. **Freshness:** Code expires after timeout or single use
4. **Uniqueness:** Each block event generates a new code

### Why This Works

| Attack Vector | Mitigation |
|---------------|------------|
| Pre-scripted bypass | Code is random, cannot be predicted |
| Slow automated analysis | Timeout prevents lengthy computation |
| Replay attack | Code is single-use and time-limited |
| Brute force | Limited attempts within timeout |
| Simple bots | Cannot parse terminal output reliably |

### What This Does NOT Prevent

- Advanced multi-modal agents with vision + fast response capability
- Humans intentionally bypassing protections
- Physical access to the terminal

These are considered out-of-scope. The goal is to prevent *automated* bypass by standard AI coding agents, not to prevent all possible bypass scenarios.

---

## Specification

### Verification Code Generation

```rust
/// Generate a cryptographically secure verification code.
///
/// Properties:
/// - Characters: lowercase a-z and digits 0-9 (36 symbols)
/// - Length: configurable (default 4)
/// - Entropy: 4 chars = ~20.7 bits, 6 chars = ~31 bits
fn generate_verification_code(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}
```

### Timeout Behavior

1. Display code and start countdown
2. Read user input with timeout
3. On timeout: deny and exit
4. On input: validate code, then proceed or deny

### Input Validation

- Case-insensitive comparison (reduce typo frustration)
- Trim whitespace from input
- Single attempt per code (no retries with same code)
- On failure: generate new code, restart timeout

### Configuration

```toml
# ~/.config/dcg/config.toml

[interactive]
# Master switch for interactive mode
enabled = true

# Verification method: "code", "command", or "none"
# - code: Random verification code (recommended)
# - command: Full command retype (paranoid mode)
# - none: Single keypress (NOT RECOMMENDED - vulnerable)
verification = "code"

# Timeout in seconds (1-30, default 5)
timeout_seconds = 5

# Verification code length (4-8, default 4)
code_length = 4

# Allow fallback to non-interactive when stdin is not a tty
# When true: non-tty stdin causes immediate block (default)
# When false: error if stdin is not a tty
allow_non_tty_fallback = true

# Maximum attempts before lockout (1-10, default 3)
max_attempts = 3

# Lockout duration in seconds after max attempts (0 = no lockout)
lockout_seconds = 60
```

### Allowlist Scopes

When a command is allowlisted via interactive mode:

| Scope | Duration | Effect |
|-------|----------|--------|
| Once | Single execution | Command allowed this one time |
| Session | Until dcg process exits | Command allowed repeatedly |
| Temporary | 24 hours | Command allowed for 24 hours |
| Permanent | Indefinite | Added to allowlist file |

User selects scope after successful verification:

```
Verification successful!

Allowlist scope for this command:
  [o] Once (this execution only)
  [s] Session (until you close this terminal)
  [t] Temporary (24 hours)
  [p] Permanent (add to project allowlist)

Choice: _
```

---

## Implementation Requirements

### R1: Secure Random Generation

- MUST use cryptographically secure RNG (`rand::thread_rng()` or better)
- MUST NOT use predictable seeds (time-based, PID-based, etc.)

### R2: Constant-Time Comparison

- MUST use constant-time string comparison to prevent timing attacks
- Example: `subtle::ConstantTimeEq` or equivalent

### R3: TTY Detection

- MUST detect if stdin is a TTY
- If not a TTY: immediate block (agent cannot interact safely)
- This is a critical security check

### R4: Timeout Enforcement

- MUST enforce timeout on input reads
- MUST handle interrupt signals gracefully
- MUST NOT allow timeout bypass via signal manipulation

### R5: Visual Feedback

- MUST display countdown to user
- MUST clear/overwrite code after timeout (prevent lingering display)
- SHOULD use terminal colors for visibility (red for warning, etc.)

### R6: Audit Logging

- MUST log all interactive bypass attempts (success and failure)
- Log format: timestamp, command, code (hash only), result, TTY info
- Logs enable detection of automated bypass attempts

---

## Testing Requirements

### Unit Tests

| Test Case | Expected Behavior |
|-----------|------------------|
| Code generation | Correct length, valid characters |
| Timeout expires | Command blocked |
| Correct code in time | Command allowed |
| Incorrect code | New code generated, retry allowed |
| Non-TTY stdin | Immediate block, no prompt |
| Max attempts exceeded | Lockout triggered |

### Integration Tests

| Scenario | Expected Behavior |
|----------|------------------|
| Human user flow | Successful allowlist |
| Piped input (simulated agent) | Immediate block |
| Timeout edge cases | Graceful handling |
| Config variations | Respect all settings |

### Security Tests

| Test | Purpose |
|------|---------|
| RNG quality | Verify code randomness |
| Timing analysis | Verify constant-time comparison |
| TTY spoofing | Verify TTY detection robustness |

---

## Future Considerations

### Multi-Modal Agent Defense

As AI agents gain vision capabilities (screenshots, OCR), the verification code approach may become vulnerable. Future enhancements could include:

1. **Animated codes:** Code changes mid-display, requiring continuous attention
2. **Audio verification:** Speak a code that the user types
3. **Hardware tokens:** U2F/FIDO2 for high-security environments

These are not currently implemented but may be added if the threat landscape evolves.

### Honeypot Detection

Consider adding detectable "honeypot" patterns that agents might try to exploit:

```
# Fake easy bypass that logs attempt
Press 'y' to allow:
[Logged: automated bypass attempt detected]
```

This enables detection of compromised agents without providing actual bypass capability.

---

## Related Documents

- [docs/security.md](security.md) — Heredoc detection security model
- [docs/allow-once-usage.md](allow-once-usage.md) — Allow-once workflow documentation
- [docs/configuration.md](configuration.md) — Configuration reference

---

## Changelog

| Date | Change |
|------|--------|
| 2026-01-19 | Initial design document created |
