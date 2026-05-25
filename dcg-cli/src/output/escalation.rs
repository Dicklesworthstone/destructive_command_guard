//! Escalation message formatting for the graduated response system.
//!
//! Renders distinct messages for Warning, SoftBlock, and HardBlock levels
//! with clear visual distinction, occurrence counts, and remediation steps.
//! Works in both TTY and non-TTY (plain text) environments.

use crate::evaluator::GraduatedResponse;
use std::fmt::Write;

/// Information needed to format an escalation message.
#[derive(Debug, Clone)]
pub struct EscalationContext<'a> {
    /// The command that triggered the response.
    pub command: &'a str,
    /// Pattern identifier (e.g., "core.git:reset-hard").
    pub pattern_id: Option<&'a str>,
    /// Severity label (e.g., "Critical", "High").
    pub severity_label: Option<&'a str>,
    /// The reason the command was flagged.
    pub reason: Option<&'a str>,
    /// Whether the bypass was applied (--force).
    pub was_bypassed: bool,
}

/// Format an escalation message for the given graduated response level.
///
/// Returns a plain-text message suitable for stderr output.
/// Each level has distinct formatting:
/// - **Warning**: informational, command is allowed
/// - **SoftBlock**: command denied, shows bypass instructions
/// - **HardBlock**: command denied, shows allowlist instructions
#[must_use]
pub fn format_escalation_message(
    response: &GraduatedResponse,
    ctx: &EscalationContext<'_>,
) -> String {
    match response {
        GraduatedResponse::Warning { occurrence } => format_warning(*occurrence, ctx),
        GraduatedResponse::SoftBlock { occurrence } => format_soft_block(*occurrence, ctx),
        GraduatedResponse::HardBlock { total_occurrences } => {
            format_hard_block(*total_occurrences, ctx)
        }
    }
}

fn format_warning(occurrence: u32, ctx: &EscalationContext<'_>) -> String {
    // Clamp to at least 1: occurrence is 1-indexed (the current attempt is
    // the n-th). A producer that passes 0 would otherwise yield "0th
    // attempt" — nonsense to a reader. Defense in depth; producers should
    // guarantee 1..=u32::MAX.
    let occurrence = occurrence.max(1);
    let mut out = String::new();
    let _ = writeln!(out, "WARNING: Potentially dangerous command detected");
    let _ = writeln!(out);
    let _ = writeln!(out, "  Command: {}", ctx.command);
    if let Some(pattern) = ctx.pattern_id {
        let _ = writeln!(out, "  Pattern: {pattern}");
    }
    if let Some(severity) = ctx.severity_label {
        let _ = writeln!(out, "  Severity: {severity}");
    }
    if let Some(reason) = ctx.reason {
        let _ = writeln!(out, "  Reason: {reason}");
    }
    let _ = writeln!(out);
    let ordinal = ordinal_suffix(occurrence);
    let _ = writeln!(
        out,
        "  This is your {occurrence}{ordinal} attempt this session. Command allowed."
    );
    let _ = writeln!(out, "  Future attempts may be blocked.");
    out
}

fn format_soft_block(occurrence: u32, ctx: &EscalationContext<'_>) -> String {
    let occurrence = occurrence.max(1);
    let mut out = String::new();
    if ctx.was_bypassed {
        let _ = writeln!(
            out,
            "SOFT BLOCK BYPASSED (--force): Repeated dangerous command"
        );
    } else {
        let _ = writeln!(out, "SOFT BLOCK: Repeated dangerous command");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "  Command: {}", ctx.command);
    if let Some(pattern) = ctx.pattern_id {
        let _ = writeln!(out, "  Pattern: {pattern}");
    }
    if let Some(severity) = ctx.severity_label {
        let _ = writeln!(out, "  Severity: {severity}");
    }
    if let Some(reason) = ctx.reason {
        let _ = writeln!(out, "  Reason: {reason}");
    }
    let _ = writeln!(out, "  Occurrences: {occurrence} this session");
    let _ = writeln!(out);
    if ctx.was_bypassed {
        let _ = writeln!(out, "  Command allowed via --force bypass.");
    } else {
        let _ = writeln!(
            out,
            "  This command was warned previously and is now soft-blocked."
        );
        // Shell-quote the command before interpolating so a copy-paste of
        // these lines into a real shell can never inadvertently run a
        // chained command. Without this, a blocked command like
        // `git reset --hard"; rm -rf / #` would render a copy-paste hint
        // that, when pasted, executes the chained `rm -rf /`.
        let quoted = shell_single_quote(ctx.command);
        let _ = writeln!(out, "  To proceed: dcg test --force {quoted}");
        let _ = writeln!(out, "  Or allowlist: dcg allow-once {quoted}");
    }
    out
}

fn format_hard_block(total_occurrences: u32, ctx: &EscalationContext<'_>) -> String {
    let total_occurrences = total_occurrences.max(1);
    let mut out = String::new();
    // Adjust the header for the first-occurrence case (Paranoid mode hard-
    // blocks immediately, so "after repeated attempts" reads as nonsense
    // when occurrences == 1).
    if total_occurrences == 1 {
        let _ = writeln!(out, "BLOCKED: Critical command blocked");
    } else {
        let _ = writeln!(out, "BLOCKED: Command blocked after repeated attempts");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "  Command: {}", ctx.command);
    if let Some(pattern) = ctx.pattern_id {
        let _ = writeln!(out, "  Pattern: {pattern}");
    }
    if let Some(severity) = ctx.severity_label {
        let _ = writeln!(out, "  Severity: {severity}");
    }
    if let Some(reason) = ctx.reason {
        let _ = writeln!(out, "  Reason: {reason}");
    }
    let _ = writeln!(out, "  Occurrences: {total_occurrences} this session");
    let _ = writeln!(out);
    if total_occurrences > 1 {
        let _ = writeln!(
            out,
            "  This command has been blocked due to repeated attempts."
        );
    }
    let _ = writeln!(out, "  Hard blocks cannot be bypassed with --force.");
    if let Some(pattern) = ctx.pattern_id {
        // `<your reason>` makes it obvious this is a placeholder, not a
        // literal flag value to copy verbatim.
        let _ = writeln!(
            out,
            "  To allowlist this rule: dcg allow \"{pattern}\" -r \"<your reason>\""
        );
    }
    out
}

/// Wrap `s` in single quotes for safe shell interpolation. The transform
/// is the standard POSIX one: any `'` inside the string is replaced with
/// `'\''` (close-quote, escaped quote, reopen-quote). The result is always
/// safe to interpolate into a single shell word.
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn ordinal_suffix(n: u32) -> &'static str {
    match n % 100 {
        11..=13 => "th",
        _ => match n % 10 {
            1 => "st",
            2 => "nd",
            3 => "rd",
            _ => "th",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx(command: &str) -> EscalationContext<'_> {
        EscalationContext {
            command,
            pattern_id: Some("core.git:reset-hard"),
            severity_label: Some("High"),
            reason: Some("Destroys uncommitted work"),
            was_bypassed: false,
        }
    }

    #[test]
    fn warning_contains_command_and_pattern() {
        let msg = format_escalation_message(
            &GraduatedResponse::Warning { occurrence: 1 },
            &test_ctx("git reset --hard"),
        );
        assert!(msg.contains("WARNING:"));
        assert!(msg.contains("git reset --hard"));
        assert!(msg.contains("core.git:reset-hard"));
        assert!(msg.contains("High"));
        assert!(msg.contains("Destroys uncommitted work"));
        assert!(msg.contains("1st attempt"));
        assert!(msg.contains("Command allowed"));
    }

    #[test]
    fn warning_ordinals() {
        let ctx = test_ctx("cmd");
        let msg1 = format_warning(1, &ctx);
        assert!(msg1.contains("1st attempt"));
        let msg2 = format_warning(2, &ctx);
        assert!(msg2.contains("2nd attempt"));
        let msg3 = format_warning(3, &ctx);
        assert!(msg3.contains("3rd attempt"));
        let msg4 = format_warning(4, &ctx);
        assert!(msg4.contains("4th attempt"));
        let msg11 = format_warning(11, &ctx);
        assert!(msg11.contains("11th attempt"));
        let msg21 = format_warning(21, &ctx);
        assert!(msg21.contains("21st attempt"));
    }

    #[test]
    fn soft_block_shows_bypass_instructions() {
        let msg = format_escalation_message(
            &GraduatedResponse::SoftBlock { occurrence: 2 },
            &test_ctx("docker system prune"),
        );
        assert!(msg.contains("SOFT BLOCK:"));
        assert!(msg.contains("docker system prune"));
        assert!(msg.contains("Occurrences: 2"));
        assert!(msg.contains("dcg test --force"));
        assert!(msg.contains("dcg allow-once"));
        // Copy-paste hint must use single-quoted form for shell safety.
        assert!(msg.contains("dcg test --force 'docker system prune'"));
        assert!(msg.contains("dcg allow-once 'docker system prune'"));
        assert!(!msg.contains("BYPASSED"));
    }

    #[test]
    fn soft_block_shell_quotes_command_against_chained_injection() {
        // A blocked command crafted to break out of double quotes should
        // produce a single-quoted copy-paste hint that is shell-safe.
        // Without `shell_single_quote`, the rendered hint looked like:
        //   dcg test --force "git reset --hard"; rm -rf / #"
        // which when copied into a shell would execute `rm -rf /`.
        let attack = r#"git reset --hard"; rm -rf / #"#;
        let mut ctx = test_ctx(attack);
        ctx.pattern_id = Some("core.git:reset-hard");
        let msg = format_escalation_message(&GraduatedResponse::SoftBlock { occurrence: 2 }, &ctx);
        // Find the `dcg test --force` line and check that:
        // 1. The argument is wrapped in single quotes (not double quotes).
        // 2. The injected `; rm -rf /` is INSIDE the single quotes, so the
        //    line ends with the closing single quote — not a chained command.
        let line = msg
            .lines()
            .find(|l| l.contains("dcg test --force"))
            .expect("missing dcg test --force line");
        let arg_part = line
            .split_once("--force ")
            .map(|(_, rest)| rest.trim_end())
            .expect("missing argument after --force");
        // The argument must be wrapped in single quotes.
        assert!(
            arg_part.starts_with('\'') && arg_part.ends_with('\''),
            "expected single-quoted argument; got: {arg_part:?}"
        );
        // The attack string must be contained inside the quoted arg (i.e.
        // the destructive `; rm -rf /` is data, not a chained command).
        assert!(
            arg_part.contains("rm -rf /"),
            "attack payload should appear inside the quoted arg: {arg_part:?}"
        );
        // The single-quoted region opens at byte 0 and closes at the last
        // byte; nothing must follow the closing quote on the same line.
        // (We already trimmed trailing whitespace, so the closing `'` must
        // be the final byte.)
        let last_quote_byte_idx = arg_part.rfind('\'').unwrap();
        assert_eq!(
            last_quote_byte_idx,
            arg_part.len() - 1,
            "expected nothing after the closing single quote; got tail: {:?}",
            &arg_part[last_quote_byte_idx + 1..]
        );
    }

    #[test]
    fn shell_single_quote_handles_embedded_single_quotes() {
        // POSIX trick: `'\''` to embed a single quote inside a single-
        // quoted string (close-quote, escaped quote, reopen-quote).
        let q = shell_single_quote("rm 'oops'");
        assert_eq!(q, "'rm '\\''oops'\\'''");
    }

    #[test]
    fn soft_block_bypassed_shows_force_message() {
        let mut ctx = test_ctx("docker system prune");
        ctx.was_bypassed = true;
        let msg = format_escalation_message(&GraduatedResponse::SoftBlock { occurrence: 2 }, &ctx);
        assert!(msg.contains("BYPASSED"));
        assert!(msg.contains("--force"));
        assert!(msg.contains("Command allowed via --force bypass"));
        assert!(!msg.contains("To proceed:"));
    }

    #[test]
    fn hard_block_shows_allowlist_instructions() {
        let msg = format_escalation_message(
            &GraduatedResponse::HardBlock {
                total_occurrences: 5,
            },
            &test_ctx("rm -rf /"),
        );
        assert!(msg.contains("BLOCKED:"));
        assert!(msg.contains("rm -rf /"));
        assert!(msg.contains("Occurrences: 5"));
        assert!(msg.contains("cannot be bypassed"));
        assert!(msg.contains("dcg allow"));
    }

    #[test]
    fn hard_block_no_force_instruction() {
        let msg = format_escalation_message(
            &GraduatedResponse::HardBlock {
                total_occurrences: 3,
            },
            &test_ctx("git reset --hard"),
        );
        assert!(!msg.contains("dcg test --force"));
        assert!(msg.contains("cannot be bypassed with --force"));
    }

    #[test]
    fn minimal_context_no_panic() {
        let ctx = EscalationContext {
            command: "rm -rf /",
            pattern_id: None,
            severity_label: None,
            reason: None,
            was_bypassed: false,
        };
        let msg = format_escalation_message(&GraduatedResponse::Warning { occurrence: 1 }, &ctx);
        assert!(msg.contains("rm -rf /"));
        assert!(msg.contains("WARNING:"));
        assert!(!msg.contains("Pattern:"));
        assert!(!msg.contains("Severity:"));
    }

    #[test]
    fn all_levels_produce_nonempty_output() {
        let ctx = test_ctx("test cmd");
        for response in [
            GraduatedResponse::Warning { occurrence: 1 },
            GraduatedResponse::SoftBlock { occurrence: 2 },
            GraduatedResponse::HardBlock {
                total_occurrences: 3,
            },
        ] {
            let msg = format_escalation_message(&response, &ctx);
            assert!(!msg.is_empty(), "empty output for {:?}", response);
            assert!(msg.contains("test cmd"));
        }
    }

    #[test]
    fn ordinal_suffix_edge_cases() {
        assert_eq!(ordinal_suffix(0), "th");
        assert_eq!(ordinal_suffix(1), "st");
        assert_eq!(ordinal_suffix(2), "nd");
        assert_eq!(ordinal_suffix(3), "rd");
        assert_eq!(ordinal_suffix(4), "th");
        assert_eq!(ordinal_suffix(11), "th");
        assert_eq!(ordinal_suffix(12), "th");
        assert_eq!(ordinal_suffix(13), "th");
        assert_eq!(ordinal_suffix(21), "st");
        assert_eq!(ordinal_suffix(22), "nd");
        assert_eq!(ordinal_suffix(23), "rd");
        assert_eq!(ordinal_suffix(100), "th");
        assert_eq!(ordinal_suffix(101), "st");
        assert_eq!(ordinal_suffix(111), "th");
        assert_eq!(ordinal_suffix(112), "th");
        assert_eq!(ordinal_suffix(113), "th");
    }
}
