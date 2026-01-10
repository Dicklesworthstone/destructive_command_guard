use destructive_command_guard::{ExtractionLimits, ExtractionResult, extract_content};

#[test]
fn test_heredoc_squiggly_delimiter_deeper_indent() {
    // Delimiter indented deeper than body
    // Body has 2 spaces indent. Delimiter has 6 spaces.
    let cmd = "cat <<~EOF\n  line1\n      EOF";

    let result = extract_content(cmd, &ExtractionLimits::default());

    if let ExtractionResult::Extracted(contents) = result {
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].content, "line1");
    } else {
        panic!("Failed to extract heredoc with deeper delimiter indent: {result:?}");
    }
}

#[test]
fn test_heredoc_squiggly_delimiter_shallower_indent() {
    // Delimiter indented less than body
    // Body has 4 spaces indent. Delimiter has 2 spaces.
    let cmd = "cat <<~EOF\n    line1\n  EOF";

    let result = extract_content(cmd, &ExtractionLimits::default());

    if let ExtractionResult::Extracted(contents) = result {
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].content, "line1");
    } else {
        panic!("Failed to extract heredoc with shallower delimiter indent: {result:?}");
    }
}

#[test]
fn test_heredoc_squiggly_delimiter_zero_body_indent() {
    // Body has 0 indent. Delimiter has 2 spaces.
    let cmd = "cat <<~EOF\nline1\n  EOF";

    let result = extract_content(cmd, &ExtractionLimits::default());

    if let ExtractionResult::Extracted(contents) = result {
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].content, "line1");
    } else {
        panic!("Failed to extract heredoc with zero body indent: {result:?}");
    }
}
