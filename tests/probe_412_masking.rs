//! Public-API contract for issue #412's fix: heredoc-body masking must not be
//! decided by data bytes inside the body.
//!
//! NOTE: this file is named `probe_*` because it started as scratch
//! instrumentation while diagnosing #412. Its assertions are real, but the name
//! does not follow the repository's `repro_<issue>_*` convention and it overlaps
//! `repro_412_quoted_heredoc_commit_message.rs`. Fold it in and remove it.

use destructive_command_guard::heredoc::mask_non_expanding_data_heredocs;

/// The reported command: an unbalanced `"` from a German quotation mark inside
/// `"$(cat <<'EOF' … )"`. The body must still be masked out of the raw-shell
/// rescan, exactly as the balanced spelling already was.
#[test]
fn a_quoted_heredoc_body_is_masked_whatever_bytes_it_carries() {
    let cases = [
        // Balanced quotes: worked before the fix.
        "git commit -q -m \"$(cat <<'EOF'\na \"b\" c\nRead-only\nEOF\n)\"",
        // Unbalanced quote nested in a command substitution: the reported case.
        "git commit -q -m \"$(cat <<'EOF'\n\u{201e}Messen\"\nRead-only\nEOF\n)\"",
        // The same body reaching git directly, which also worked before.
        "git commit -q -F - <<'EOF'\na \" b\nRead-only\nEOF",
    ];
    for command in cases {
        let masked = mask_non_expanding_data_heredocs(command);
        assert_ne!(
            masked.as_ref(),
            command,
            "quoted heredoc body must be masked: {command:?}"
        );
        assert!(
            !masked.contains("Read-only"),
            "the verb-noun-shaped word must not survive into the rescan view: {masked:?}"
        );
        assert_eq!(
            masked.len(),
            command.len(),
            "masking preserves byte offsets: {command:?}"
        );
    }
}

/// An expanding heredoc body is evaluated by the shell, so it is never masked
/// by this function — the fix must not have widened that.
#[test]
fn an_expanding_heredoc_body_is_not_masked() {
    let command = "cat <<EOF\n$(rm -rf /)\nEOF";
    assert_eq!(
        mask_non_expanding_data_heredocs(command).as_ref(),
        command,
        "an unquoted delimiter expands and must stay visible"
    );
}
