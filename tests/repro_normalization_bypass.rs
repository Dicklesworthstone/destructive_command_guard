use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::{CompiledOverrides, Config};
use destructive_command_guard::evaluator::evaluate_command;

fn evaluate(cmd: &str) -> bool {
    let config = Config::default();
    let compiled = CompiledOverrides::default();
    let allowlists = LayeredAllowlist::default();
    let keywords = &["git", "rm"]; // Keywords that might trigger

    let result = evaluate_command(cmd, &config, keywords, &compiled, &allowlists);

    result.is_denied()
}

#[test]
fn test_backslash_exe_bypass() {
    // This should be blocked, but if normalization fails, it might be allowed.
    // \git.exe avoids strip_leading_backslash (due to '.')
    // and avoids PATH_NORMALIZER (doesn't start with /)
    // and avoids regex "git\s+" (due to .exe)
    let cmd = "\\git.exe reset --hard";
    assert!(evaluate(cmd), "Command '{cmd}' should be blocked");
}

#[test]
fn test_windows_path_bypass() {
    // Windows path logic
    let cmd = "C:/Program Files/Git/bin/git.exe reset --hard";
    assert!(evaluate(cmd), "Command '{cmd}' should be blocked");
}

#[test]
fn test_cpp_binary_normalization() {
    // \g++ should be normalized to g++ (if g++ was a guarded command, which it isn't usually,
    // but implies the strictness issue).
    // Let's use a hypothetical guarded command that has a + or .
    // For now, just verifying git/rm behavior.

    // \rm.exe -rf /
    let cmd = "\\rm.exe -rf /";
    assert!(evaluate(cmd), "Command '{cmd}' should be blocked");
}
