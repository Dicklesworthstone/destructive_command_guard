#[cfg(test)]
mod tests {
    use destructive_command_guard::context::{SpanKind, classify_command};

    #[test]
    fn test_python_u_c_bypass() {
        // python -u -c "..."
        // -u is unbuffered output. Common flag.
        let cmd = "python -u -c \"import os; os.system('rm -rf /')\"";
        let spans = classify_command(cmd);

        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.text(cmd).contains("import os"));

        // This fails if it's classified as Argument (safe) instead of InlineCode (dangerous)
        assert_eq!(
            inline_span.unwrap().kind,
            SpanKind::InlineCode,
            "Failed to detect inline code with intervening flag"
        );
    }

    #[test]
    fn test_bash_e_c_bypass() {
        // bash -e -c "..."
        let cmd = "bash -e -c \"rm -rf /\"";
        let spans = classify_command(cmd);

        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.text(cmd).contains("rm -rf"));

        assert_eq!(
            inline_span.unwrap().kind,
            SpanKind::InlineCode,
            "Failed to detect inline code with intervening flag"
        );
    }
}
