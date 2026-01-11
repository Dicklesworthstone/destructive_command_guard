#[cfg(test)]
mod tests {
    use destructive_command_guard::heredoc::ScriptLanguage;

    #[test]
    fn test_env_flag_argument_handling() {
        let cmd = "env -u USER python3 -c 'print(1)'";
        let (lang, _) = ScriptLanguage::detect(cmd, "");
        assert_eq!(
            lang,
            ScriptLanguage::Python,
            "Failed to detect python after env -u USER"
        );
    }

    #[test]
    fn test_env_chdir_handling() {
        let cmd = "env -C /tmp python3 -c 'print(1)'";
        let (lang, _) = ScriptLanguage::detect(cmd, "");
        assert_eq!(
            lang,
            ScriptLanguage::Python,
            "Failed to detect python after env -C /tmp"
        );
    }
}
