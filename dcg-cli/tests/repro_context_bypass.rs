use dcg_cli::context::{SpanKind, classify_command};

#[test]
fn test_bash_rcfile_inline_bypass() {
    // This command uses an argument (--rcfile "my file") that naively splitting by whitespace
    // would break into ["\"my", "file\""], neither of which looks like "bash".
    // If the classifier fails to identify "bash", it won't treat -c content as InlineCode.
    // InlineCode requires pattern check. Argument does not.
    // So this is a bypass if classification fails.
    let cmd = "bash --rcfile \"my file\" -c \"rm -rf /\"";
    let spans = classify_command(cmd);

    let inline_span = spans
        .spans()
        .iter()
        .find(|s| s.text(cmd).contains("rm -rf"));

    assert!(inline_span.is_some(), "Should find the rm -rf span");
    let span = inline_span.unwrap();

    // It MUST be InlineCode (or Executed/Unknown/HeredocBody).
    // It MUST NOT be Argument or Data.
    println!("Span kind: {:?}", span.kind);
    assert!(
        span.kind.requires_pattern_check(),
        "Span should require pattern check, but got {:?}",
        span.kind
    );
}

#[test]
fn test_complex_args_bypass() {
    // Another variant with multiple args
    let cmd = "python -B -v -c \"import os; os.system('rm -rf /')\"";
    let spans = classify_command(cmd);

    let inline_span = spans
        .spans()
        .iter()
        .find(|s| s.kind == SpanKind::InlineCode);
    assert!(
        inline_span.is_some(),
        "Should detect python -c even with multiple flags"
    );
}
