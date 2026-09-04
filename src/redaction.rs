//! Pattern-based secret redaction for anything dcg persists.
//!
//! dcg writes command text to three places that outlive the hook invocation:
//! the history database, the `[general] log_file`, and the pending-exception
//! store used by allow-once. A blocked command frequently *is* the incident —
//! `curl -H "Authorization: Bearer …"`, a `psql postgres://user:pw@…` URL, an
//! `rm -rf` next to a deploy key — so the command text is exactly where
//! credentials show up.
//!
//! [`redact_secrets`] rewrites recognised credential shapes to bracketed
//! placeholders before any of those writers see the string. It is deliberately
//! conservative: every pattern is anchored on a distinctive prefix, a scheme,
//! or an explicit `key = value` assignment, so ordinary commands pass through
//! untouched. It is a mitigation, not a guarantee — an unrecognised secret
//! shape still reaches storage, which is what `redaction_mode = "full"` is
//! for.
//!
//! Ordering matters: the specific token patterns run before the generic
//! `password=` / `secret=` assignment patterns, and those generic patterns
//! exclude `[` and `]` so they cannot re-redact a placeholder a previous
//! pattern already wrote.

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

/// Credential shapes recognised by [`redact_secrets`], as
/// `(pattern, replacement)`.
///
/// Replacements are expanded, so `$1` refers to the first capture group; a
/// replacement must never contain a bare `$` otherwise (enforced by a unit
/// test below).
const SECRET_PATTERNS: &[(&str, &str)] = &[
    // ---- Provider API keys -------------------------------------------------
    (r"sk-ant-api[A-Za-z0-9\-_]{20,}", "[ANTHROPIC_KEY]"),
    // OpenAI: sk-…, sk-proj-…, sk-svcacct-… all share the sk- prefix and are
    // long; the length floor keeps this off short `sk-` flag values.
    (r"sk-[A-Za-z0-9\-_]{40,}", "[OPENAI_KEY]"),
    (r"AIza[A-Za-z0-9_\-]{35}", "[GOOGLE_API_KEY]"),
    // Stripe live/test secret and restricted keys.
    (r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}", "[STRIPE_KEY]"),
    (
        r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
        "[SENDGRID_KEY]",
    ),
    // ---- Cloud provider secrets -------------------------------------------
    (
        r"A(?:KIA|SIA|IDA|ROA|IPA|NPA|NVA)[A-Z0-9]{16}",
        "[AWS_ACCESS_KEY]",
    ),
    (
        r#"(?i)aws_secret_access_key\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]+)"#,
        "[AWS_SECRET]",
    ),
    (
        r#"(?i)azure[_\-]?(?:storage|account)[_\-]?key\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]+)"#,
        "[AZURE_KEY]",
    ),
    // ---- Forge and registry tokens ----------------------------------------
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "[GITHUB_TOKEN]"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "[GITHUB_TOKEN]"),
    (r"glpat-[A-Za-z0-9\-_]{20,}", "[GITLAB_PAT]"),
    (r"npm_[A-Za-z0-9]{36}", "[NPM_TOKEN]"),
    (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]+", "[PYPI_TOKEN]"),
    (r"dop_v1_[a-f0-9]{64}", "[DIGITALOCEAN_TOKEN]"),
    (r"xox[baprse]-[A-Za-z0-9\-]{10,}", "[SLACK_TOKEN]"),
    (
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
        "[SLACK_WEBHOOK]",
    ),
    // ---- Key material ------------------------------------------------------
    (
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        "[PRIVATE_KEY]",
    ),
    (
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "[PGP_PRIVATE_KEY]",
    ),
    // JWT: header.payload.signature, each segment base64url.
    (
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "[JWT_TOKEN]",
    ),
    // ---- Transport-level credentials --------------------------------------
    // `Authorization: Bearer <token>` / `-H "Authorization: Basic <blob>"`.
    (
        r"(?i)(authorization\s*:\s*)(?:bearer|basic|token)\s+[A-Za-z0-9._\-+/=]+",
        "${1}[AUTH_HEADER]",
    ),
    // Any `scheme://user[:password]@host`, which covers postgres, mysql,
    // mongodb(+srv), redis, amqp, ssh, and the `git clone https://token@host`
    // shape the allow-once documentation describes. The scheme is preserved so
    // the surviving text still identifies the command.
    (
        r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/@]+@",
        "${1}[URL_CREDENTIALS]@",
    ),
    // ---- Generic assignments (last: they must not eat placeholders) -------
    (
        r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]{8,})"#,
        "[PASSWORD]",
    ),
    (
        r#"(?i)(?:secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]{16,})"#,
        "[SECRET]",
    ),
];

/// The compiled pattern set.
///
/// `regexes` and `set` are built from the same filtered pattern list, so a
/// `RegexSet` match index addresses the same entry in `regexes`. A pattern
/// that fails to compile is dropped from both rather than panicking — a broken
/// pattern must not take down the hook — and `patterns_all_compile` below
/// keeps the shipped set honest.
struct Compiled {
    regexes: Vec<(Regex, &'static str)>,
    /// `None` only if `RegexSet` construction itself fails (e.g. the combined
    /// program exceeds the size limit); callers then run every pattern.
    set: Option<RegexSet>,
}

static COMPILED: LazyLock<Compiled> = LazyLock::new(|| {
    let usable: Vec<(Regex, &'static str)> = SECRET_PATTERNS
        .iter()
        .filter_map(|(pattern, replacement)| Regex::new(pattern).ok().map(|re| (re, *replacement)))
        .collect();
    let set = RegexSet::new(usable.iter().map(|(re, _)| re.as_str())).ok();
    Compiled {
        regexes: usable,
        set,
    }
});

/// Replace recognised credential shapes in `command` with placeholders.
///
/// Returns the input unchanged when nothing matches. This is a best-effort
/// mitigation over known shapes, not a guarantee that the result is free of
/// secrets.
#[must_use]
pub fn redact_secrets(command: &str) -> String {
    let compiled = &*COMPILED;
    let Some(set) = compiled.set.as_ref() else {
        // The set failed to build; fall back to running every pattern.
        return compiled
            .regexes
            .iter()
            .fold(command.to_string(), |acc, (re, rep)| {
                re.replace_all(&acc, *rep).into_owned()
            });
    };

    // dcg runs on every `PreToolUse` call, so the overwhelmingly common case —
    // a command with no credentials in it — must not pay for 20-odd separate
    // scans and allocations. `RegexSet::matches` answers "which patterns
    // match" in one pass over the input.
    let matched = set.matches(command);
    if !matched.matched_any() {
        return command.to_string();
    }

    // `matches.iter()` yields indices in ascending order, so replacement runs
    // in declaration order and the specific token patterns land before the
    // generic assignment patterns. Only patterns that matched the original
    // string are run: every replacement either deletes secret text outright or
    // (for the URL and Authorization patterns) keeps back only the scheme or
    // the header name, so a replacement can never expose a credential that was
    // not already visible.
    let mut result = command.to_string();
    for index in &matched {
        if let Some((regex, replacement)) = compiled.regexes.get(index) {
            result = regex.replace_all(&result, *replacement).into_owned();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{SECRET_PATTERNS, redact_secrets};

    /// Every shipped pattern must compile; `redact_secrets` silently drops the
    /// ones that do not, which would be a silent loss of coverage.
    #[test]
    fn patterns_all_compile() {
        for (pattern, _) in SECRET_PATTERNS {
            assert!(
                regex::Regex::new(pattern).is_ok(),
                "pattern failed to compile: {pattern}"
            );
        }
    }

    /// Replacements are expanded, so a stray `$` would silently swallow the
    /// following characters as a capture-group name.
    #[test]
    fn replacements_use_dollar_only_for_capture_groups() {
        for (_, replacement) in SECRET_PATTERNS {
            for (index, byte) in replacement.bytes().enumerate() {
                if byte == b'$' {
                    assert!(
                        replacement[index..].starts_with("${"),
                        "replacement has a bare $: {replacement}"
                    );
                }
            }
        }
    }

    // Every token below is synthetic and structurally valid only.
    #[test]
    fn redacts_bare_provider_tokens() {
        let command = "deploy AKIAABCDEFGHIJKLMNOP \
             ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \
             sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let redacted = redact_secrets(command);
        assert!(!redacted.contains("AKIAABCDEFGHIJKLMNOP"), "{redacted}");
        assert!(!redacted.contains("ghp_ABCDEFGHIJ"), "{redacted}");
        assert!(!redacted.contains("sk_live_ABCDEF"), "{redacted}");
        assert!(redacted.contains("[AWS_ACCESS_KEY]"), "{redacted}");
        assert!(redacted.contains("[GITHUB_TOKEN]"), "{redacted}");
        assert!(redacted.contains("[STRIPE_KEY]"), "{redacted}");
        assert!(redacted.starts_with("deploy "), "{redacted}");
    }

    #[test]
    fn redacts_url_credentials_but_keeps_the_scheme_and_host() {
        let redacted = redact_secrets(
            "git clone https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@github.com/o/r",
        );
        assert!(!redacted.contains("ghp_ABCDEFGHIJ"), "{redacted}");
        assert!(redacted.contains("https://"), "{redacted}");
        assert!(redacted.contains("@github.com/o/r"), "{redacted}");

        let dsn = redact_secrets("psql postgres://admin:hunter2hunter2@db.internal:5432/app");
        assert!(!dsn.contains("hunter2hunter2"), "{dsn}");
        assert!(!dsn.contains("admin:"), "{dsn}");
        assert!(
            dsn.contains("postgres://[URL_CREDENTIALS]@db.internal:5432/app"),
            "{dsn}"
        );
    }

    #[test]
    fn redacts_authorization_headers_and_assignments() {
        let header = redact_secrets(
            "curl -H 'Authorization: Bearer abc123.def456-ghi789' https://api.example.com",
        );
        assert!(!header.contains("abc123.def456"), "{header}");
        assert!(header.contains("[AUTH_HEADER]"), "{header}");
        assert!(header.contains("https://api.example.com"), "{header}");

        let assignment = redact_secrets("run --env PASSWORD=correcthorsebattery");
        assert!(!assignment.contains("correcthorsebattery"), "{assignment}");
        assert!(assignment.contains("[PASSWORD]"), "{assignment}");
    }

    #[test]
    fn redacts_jwts_and_private_key_headers() {
        let jwt = redact_secrets("auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl next");
        assert!(!jwt.contains("eyJhbGciOiJIUzI1NiJ9."), "{jwt}");
        assert!(jwt.contains("[JWT_TOKEN]"), "{jwt}");

        let key = redact_secrets("echo '-----BEGIN OPENSSH PRIVATE KEY-----' > k");
        assert!(key.contains("[PRIVATE_KEY]"), "{key}");
    }

    /// A placeholder written by an earlier pattern must not be re-matched by a
    /// later generic assignment pattern.
    #[test]
    fn placeholders_are_not_re_redacted() {
        let once = redact_secrets("api_key=sk-ant-apiABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
        let twice = redact_secrets(&once);
        assert_eq!(
            once, twice,
            "redaction is not idempotent: {once} -> {twice}"
        );
        assert!(!once.contains("sk-ant-api"), "{once}");
    }

    /// The overwhelmingly common case: an ordinary command must survive
    /// byte-for-byte.
    #[test]
    fn ordinary_commands_pass_through_unchanged() {
        for command in [
            "rm -rf ./build",
            "git checkout -- src/main.rs",
            "cargo test --workspace -- --nocapture",
            "ssh deploy@example.com 'systemctl restart app'",
            "curl -sSL https://example.com/install.sh | sh",
            "psql -h db.internal -U admin app",
        ] {
            assert_eq!(redact_secrets(command), command, "rewrote: {command}");
        }
    }
}
