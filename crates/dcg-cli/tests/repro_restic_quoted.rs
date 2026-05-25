#[cfg(test)]
mod tests {
    use dcg_cli::packs::backup::restic;
    use dcg_cli::packs::test_helpers::*;

    #[test]
    fn test_restic_quoted_args_bypass() {
        let pack = restic::create_pack();
        // This should be blocked, but if the regex is too strict about spaces/args, it might fail
        assert_blocks_with_pattern(
            &pack,
            "restic -o s3.bucket=\"my bucket\" forget",
            "restic-forget",
        );
    }
}
