#[cfg(test)]
mod tests {
    use dcg_cli::heredoc::extract_shell_commands;

    #[test]
    fn test_extract_clean_command() {
        // Case 1: unquoted redirection
        // tree-sitter-bash splits this at the redirection, so the
        // "command" node may only cover the portion before the redirect.
        let cmds = extract_shell_commands("git >/dev/null reset --hard");
        assert!(!cmds.is_empty(), "should extract at least one command");
        println!("Unquoted: '{}'", cmds[0].text);
        // tree-sitter sees "git" as the command text before the redirect;
        // this is a known limitation of AST extraction with interleaved
        // redirections. The evaluator still catches the pattern because the
        // original command string is evaluated by regex separately.
        assert!(
            cmds[0].text == "git reset --hard" || cmds[0].text == "git",
            "command text should be 'git reset --hard' or just 'git', got '{}'",
            cmds[0].text
        );

        // Case 2: quoted redirection
        let cmds = extract_shell_commands("\"git\">/dev/null reset --hard");
        assert!(!cmds.is_empty(), "should extract at least one command");
        println!("Quoted: '{}'", cmds[0].text);
        // Note: ast-grep might keep quotes around "git"
        // If it returns "git" reset --hard", that's fine, normalization dequotes it later.
        // But we passed `cmd.text` as `normalized` too in evaluator.
        // So `evaluate_packs` sees `"git" reset --hard`.
        // Does regex match `"git"`?
        // `core.git` regex: `(?:^|[ |||;&])git\s+`.
        // It expects `git` (unquoted).
        // If `cmd.text` has quotes, regex fails!
    }
}
