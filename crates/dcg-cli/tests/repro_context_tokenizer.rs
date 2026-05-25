#[cfg(test)]
mod tests {
    use dcg_cli::context::sanitize_for_pattern_matching;

    #[test]
    fn test_broken_tokenization_nested_quotes() {
        // The bug: consume_dollar_paren fails to recurse into double quotes.
        // If we have spaces inside the nested parens, consume_dollar_paren exits early.

        // Case 1: Simple nested quotes (worked by accident in dumb scanner due to parity)
        // echo "$(echo "inner" )"; rm -rf /
        let cmd1 = r#"echo "$(echo "inner" )"; rm -rf /"#;
        let sanitized1 = sanitize_for_pattern_matching(cmd1);
        assert!(
            sanitized1.contains("rm -rf"),
            "Case 1 failed: 'rm -rf' was masked/swallowed."
        );

        // Case 2: Nested quotes containing ')' (fails in dumb scanner)
        // The dumb scanner sees the first inner " as closing the outer string.
        // Then it sees the ) inside the inner string as an unquoted ) and returns early.
        // Result: The parsing desynchronizes and swallows the subsequent command.
        // Input: echo "$(echo " ) " )"; rm -rf /
        let cmd2 = r#"echo "$(echo " ) " )"; rm -rf /"#;
        let sanitized2 = sanitize_for_pattern_matching(cmd2);

        println!("Original:  {cmd2}");
        println!("Sanitized: {sanitized2}");

        assert!(
            sanitized2.contains("rm -rf"),
            "Case 2 (Critical) failed: 'rm -rf' was masked/swallowed due to ')' inside nested quotes."
        );
    }
}
