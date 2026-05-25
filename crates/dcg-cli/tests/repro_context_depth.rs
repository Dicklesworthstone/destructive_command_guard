#[cfg(test)]
mod tests {
    use dcg_cli::context::sanitize_for_pattern_matching;

    #[test]
    fn test_recursion_depth_limit() {
        // Construct a pathological input with >500 nested command substitutions inside quotes.
        // echo "$( $( $( ... ) ) )"
        // 501 levels deep.

        let mut deep_cmd = String::from("echo \"");
        for _ in 0..600 {
            deep_cmd.push_str("$($");
        }
        deep_cmd.push_str("echo hi");
        for _ in 0..600 {
            deep_cmd.push(')');
        }
        deep_cmd.push('"');

        // This should NOT crash (stack overflow).
        // It should hit the depth limit and fallback (consume rest of string).
        let _sanitized = sanitize_for_pattern_matching(&deep_cmd);
    }
}
